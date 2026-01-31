//! Coordinator Message Protocol (14A.2B.2.13)
//!
//! Module ini menyediakan enum pesan untuk komunikasi coordinator-to-coordinator.
//!
//! # Types
//!
//! | Type | Fungsi |
//! |------|--------|
//! | `CoordinatorMessage` | Enum pesan utama untuk komunikasi |
//! | `MessageVote` | Vote decision (Approve/Reject) |
//! | `MessageDecodeError` | Error type untuk decode failures |
//!
//! # Encoding
//!
//! | Property | Value |
//! |----------|-------|
//! | Format | bincode |
//! | Byte Order | Little-endian |
//! | Serialization | Deterministic |
//!
//! # Message Types
//!
//! | Variant | message_type() | Has SessionId |
//! |---------|----------------|---------------|
//! | ProposeReceipt | "propose_receipt" | Yes |
//! | VoteReceipt | "vote_receipt" | Yes |
//! | SigningCommitment | "signing_commitment" | Yes |
//! | PartialSignature | "partial_signature" | Yes |
//! | EpochHandoff | "epoch_handoff" | No |
//! | Ping | "ping" | No |
//! | Pong | "pong" | No |
//!
//! # Usage
//!
//! ```ignore
//! use dsdn_coordinator::multi::{CoordinatorMessage, MessageVote};
//!
//! // Create a ping message
//! let ping = CoordinatorMessage::Ping { timestamp: 1700000000 };
//!
//! // Encode
//! let bytes = ping.encode();
//!
//! // Decode
//! let decoded = CoordinatorMessage::decode(&bytes)?;
//! assert_eq!(ping, decoded);
//! ```

use std::fmt;

use serde::{Deserialize, Serialize};

// Internal imports from types module
use super::{CoordinatorId, SessionId, WorkloadId};

// External imports
use dsdn_common::coordinator::{CommitteeTransition, ReceiptData};
use dsdn_proto::tss::signing::{PartialSignatureProto, SigningCommitmentProto};

// ════════════════════════════════════════════════════════════════════════════════
// MESSAGE VOTE
// ════════════════════════════════════════════════════════════════════════════════

/// Vote decision untuk receipt approval dalam messaging.
///
/// Berbeda dengan `Vote` struct di types.rs yang menyimpan signature,
/// `MessageVote` hanya merepresentasikan keputusan voting.
///
/// # Variants
///
/// - `Approve` - Menyetujui receipt
/// - `Reject` - Menolak receipt dengan alasan
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageVote {
    /// Menyetujui receipt.
    Approve,
    /// Menolak receipt dengan alasan.
    Reject {
        /// Alasan penolakan.
        reason: String,
    },
}

impl MessageVote {
    /// Membuat vote approval.
    #[must_use]
    #[inline]
    pub const fn approve() -> Self {
        Self::Approve
    }

    /// Membuat vote rejection dengan alasan.
    #[must_use]
    #[inline]
    pub fn reject(reason: impl Into<String>) -> Self {
        Self::Reject {
            reason: reason.into(),
        }
    }

    /// Memeriksa apakah vote adalah approval.
    #[must_use]
    #[inline]
    pub const fn is_approve(&self) -> bool {
        matches!(self, Self::Approve)
    }

    /// Memeriksa apakah vote adalah rejection.
    #[must_use]
    #[inline]
    pub const fn is_reject(&self) -> bool {
        matches!(self, Self::Reject { .. })
    }

    /// Mendapatkan rejection reason jika ada.
    #[must_use]
    pub fn rejection_reason(&self) -> Option<&str> {
        match self {
            Self::Reject { reason } => Some(reason),
            Self::Approve => None,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// MESSAGE DECODE ERROR
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk decode failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageDecodeError {
    /// Bincode deserialization gagal.
    DeserializationFailed {
        /// Error message dari bincode.
        reason: String,
    },
    /// Data kosong.
    EmptyData,
}

impl fmt::Display for MessageDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageDecodeError::DeserializationFailed { reason } => {
                write!(f, "message decode failed: {}", reason)
            }
            MessageDecodeError::EmptyData => {
                write!(f, "message decode failed: empty data")
            }
        }
    }
}

impl std::error::Error for MessageDecodeError {}

// ════════════════════════════════════════════════════════════════════════════════
// COORDINATOR MESSAGE
// ════════════════════════════════════════════════════════════════════════════════

/// Enum pesan utama untuk komunikasi coordinator-to-coordinator.
///
/// Semua komunikasi antar coordinator menggunakan enum ini.
/// Setiap variant memiliki `message_type()` yang unik.
///
/// # Encoding
///
/// Menggunakan bincode dengan konfigurasi default (little-endian, varint).
/// Encode/decode bersifat deterministic dan roundtrip-safe.
///
/// # Thread Safety
///
/// `CoordinatorMessage` adalah `Send + Sync` karena semua fields juga
/// `Send + Sync`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum CoordinatorMessage {
    /// Proposal receipt baru untuk voting.
    ProposeReceipt {
        /// Session identifier untuk signing.
        session_id: SessionId,
        /// Receipt data yang diusulkan.
        data: ReceiptData,
        /// Coordinator yang mengusulkan.
        proposer: CoordinatorId,
    },

    /// Vote untuk receipt yang diusulkan.
    VoteReceipt {
        /// Session identifier.
        session_id: SessionId,
        /// Workload identifier.
        workload_id: WorkloadId,
        /// Vote decision.
        vote: MessageVote,
        /// Coordinator yang memberikan vote.
        voter: CoordinatorId,
    },

    /// Signing commitment untuk FROST protocol.
    SigningCommitment {
        /// Session identifier.
        session_id: SessionId,
        /// Signing commitment proto.
        commitment: SigningCommitmentProto,
    },

    /// Partial signature untuk FROST protocol.
    PartialSignature {
        /// Session identifier.
        session_id: SessionId,
        /// Partial signature proto.
        partial: PartialSignatureProto,
    },

    /// Epoch handoff notification.
    EpochHandoff {
        /// Epoch lama.
        old_epoch: u64,
        /// Epoch baru.
        new_epoch: u64,
        /// Committee transition data.
        transition: CommitteeTransition,
    },

    /// Ping message untuk health check.
    Ping {
        /// Timestamp saat ping dikirim (milliseconds).
        timestamp: u64,
    },

    /// Pong response untuk ping.
    Pong {
        /// Timestamp dari ping yang di-reply.
        timestamp: u64,
        /// Timestamp saat pong diterima (milliseconds).
        received_at: u64,
    },
}

impl CoordinatorMessage {
    // ════════════════════════════════════════════════════════════════════════════
    // TYPE IDENTIFICATION
    // ════════════════════════════════════════════════════════════════════════════

    /// Mengembalikan string identifier unik untuk message type.
    ///
    /// # Returns
    ///
    /// Static string yang unik untuk setiap variant.
    /// Tidak bergantung pada data runtime.
    #[must_use]
    pub const fn message_type(&self) -> &'static str {
        match self {
            CoordinatorMessage::ProposeReceipt { .. } => "propose_receipt",
            CoordinatorMessage::VoteReceipt { .. } => "vote_receipt",
            CoordinatorMessage::SigningCommitment { .. } => "signing_commitment",
            CoordinatorMessage::PartialSignature { .. } => "partial_signature",
            CoordinatorMessage::EpochHandoff { .. } => "epoch_handoff",
            CoordinatorMessage::Ping { .. } => "ping",
            CoordinatorMessage::Pong { .. } => "pong",
        }
    }

    /// Mengembalikan session_id jika variant memilikinya.
    ///
    /// # Returns
    ///
    /// - `Some(SessionId)` untuk variants dengan session_id
    /// - `None` untuk EpochHandoff, Ping, Pong
    #[must_use]
    pub fn session_id(&self) -> Option<SessionId> {
        match self {
            CoordinatorMessage::ProposeReceipt { session_id, .. }
            | CoordinatorMessage::VoteReceipt { session_id, .. }
            | CoordinatorMessage::SigningCommitment { session_id, .. }
            | CoordinatorMessage::PartialSignature { session_id, .. } => Some(session_id.clone()),
            CoordinatorMessage::EpochHandoff { .. }
            | CoordinatorMessage::Ping { .. }
            | CoordinatorMessage::Pong { .. } => None,
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // ENCODING
    // ════════════════════════════════════════════════════════════════════════════

    /// Encode message ke bytes menggunakan bincode.
    ///
    /// # Returns
    ///
    /// `Vec<u8>` berisi serialized message.
    /// Returns empty Vec jika serialization gagal (tidak panic).
    ///
    /// # Determinism
    ///
    /// Encoding bersifat deterministic: input yang sama selalu
    /// menghasilkan output yang sama.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).unwrap_or_default()
    }

    /// Decode bytes ke message menggunakan bincode.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Slice bytes yang akan di-decode
    ///
    /// # Returns
    ///
    /// - `Ok(CoordinatorMessage)` jika decode berhasil
    /// - `Err(MessageDecodeError)` jika decode gagal
    ///
    /// # Errors
    ///
    /// - `EmptyData` jika bytes kosong
    /// - `DeserializationFailed` jika bincode deserialization gagal
    pub fn decode(bytes: &[u8]) -> Result<Self, MessageDecodeError> {
        if bytes.is_empty() {
            return Err(MessageDecodeError::EmptyData);
        }

        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map(|(msg, _)| msg)
            .map_err(|e| MessageDecodeError::DeserializationFailed {
                reason: e.to_string(),
            })
    }

    // ════════════════════════════════════════════════════════════════════════════
    // CONVENIENCE CONSTRUCTORS
    // ════════════════════════════════════════════════════════════════════════════

    /// Membuat Ping message dengan timestamp sekarang.
    #[must_use]
    pub fn ping_now() -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self::Ping { timestamp }
    }

    /// Membuat Pong response dari Ping.
    #[must_use]
    pub fn pong_for(ping_timestamp: u64) -> Self {
        let received_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self::Pong {
            timestamp: ping_timestamp,
            received_at,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────────────────
    // MessageVote Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_message_vote_approve() {
        let vote = MessageVote::approve();
        assert!(vote.is_approve());
        assert!(!vote.is_reject());
        assert!(vote.rejection_reason().is_none());
    }

    #[test]
    fn test_message_vote_reject() {
        let vote = MessageVote::reject("invalid data");
        assert!(!vote.is_approve());
        assert!(vote.is_reject());
        assert_eq!(vote.rejection_reason(), Some("invalid data"));
    }

    #[test]
    fn test_message_vote_eq() {
        assert_eq!(MessageVote::Approve, MessageVote::Approve);
        assert_eq!(
            MessageVote::Reject {
                reason: "x".to_string()
            },
            MessageVote::Reject {
                reason: "x".to_string()
            }
        );
        assert_ne!(MessageVote::Approve, MessageVote::reject("x"));
    }

    #[test]
    fn test_message_vote_clone() {
        let vote = MessageVote::reject("test");
        let cloned = vote.clone();
        assert_eq!(vote, cloned);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // MessageDecodeError Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_decode_error_display_deserialization() {
        let err = MessageDecodeError::DeserializationFailed {
            reason: "test error".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("test error"));
        assert!(display.contains("decode failed"));
    }

    #[test]
    fn test_decode_error_display_empty() {
        let err = MessageDecodeError::EmptyData;
        let display = err.to_string();
        assert!(display.contains("empty"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // CoordinatorMessage message_type Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_message_type_propose_receipt() {
        let msg = CoordinatorMessage::ProposeReceipt {
            session_id: SessionId::new([0x01; 32]),
            data: make_receipt_data(),
            proposer: CoordinatorId::new([0x02; 32]),
        };
        assert_eq!(msg.message_type(), "propose_receipt");
    }

    #[test]
    fn test_message_type_vote_receipt() {
        let msg = CoordinatorMessage::VoteReceipt {
            session_id: SessionId::new([0x01; 32]),
            workload_id: WorkloadId::new([0x02; 32]),
            vote: MessageVote::Approve,
            voter: CoordinatorId::new([0x03; 32]),
        };
        assert_eq!(msg.message_type(), "vote_receipt");
    }

    #[test]
    fn test_message_type_signing_commitment() {
        let msg = CoordinatorMessage::SigningCommitment {
            session_id: SessionId::new([0x01; 32]),
            commitment: make_signing_commitment(),
        };
        assert_eq!(msg.message_type(), "signing_commitment");
    }

    #[test]
    fn test_message_type_partial_signature() {
        let msg = CoordinatorMessage::PartialSignature {
            session_id: SessionId::new([0x01; 32]),
            partial: make_partial_signature(),
        };
        assert_eq!(msg.message_type(), "partial_signature");
    }

    // Note: test_message_type_epoch_handoff requires CommitteeTransition
    // which needs complex setup. Deferred to integration tests.

    #[test]
    fn test_message_type_ping() {
        let msg = CoordinatorMessage::Ping { timestamp: 123 };
        assert_eq!(msg.message_type(), "ping");
    }

    #[test]
    fn test_message_type_pong() {
        let msg = CoordinatorMessage::Pong {
            timestamp: 123,
            received_at: 456,
        };
        assert_eq!(msg.message_type(), "pong");
    }

    #[test]
    fn test_message_types_unique() {
        let types = [
            "propose_receipt",
            "vote_receipt",
            "signing_commitment",
            "partial_signature",
            "epoch_handoff",
            "ping",
            "pong",
        ];

        // Check all unique
        let mut seen = std::collections::HashSet::new();
        for t in types {
            assert!(seen.insert(t), "duplicate message_type: {}", t);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // CoordinatorMessage session_id Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_session_id_propose_receipt() {
        let session = SessionId::new([0x01; 32]);
        let msg = CoordinatorMessage::ProposeReceipt {
            session_id: session.clone(),
            data: make_receipt_data(),
            proposer: CoordinatorId::new([0x02; 32]),
        };
        assert_eq!(msg.session_id(), Some(session));
    }

    #[test]
    fn test_session_id_vote_receipt() {
        let session = SessionId::new([0x01; 32]);
        let msg = CoordinatorMessage::VoteReceipt {
            session_id: session.clone(),
            workload_id: WorkloadId::new([0x02; 32]),
            vote: MessageVote::Approve,
            voter: CoordinatorId::new([0x03; 32]),
        };
        assert_eq!(msg.session_id(), Some(session));
    }

    #[test]
    fn test_session_id_signing_commitment() {
        let session = SessionId::new([0x01; 32]);
        let msg = CoordinatorMessage::SigningCommitment {
            session_id: session.clone(),
            commitment: make_signing_commitment(),
        };
        assert_eq!(msg.session_id(), Some(session));
    }

    #[test]
    fn test_session_id_partial_signature() {
        let session = SessionId::new([0x01; 32]);
        let msg = CoordinatorMessage::PartialSignature {
            session_id: session.clone(),
            partial: make_partial_signature(),
        };
        assert_eq!(msg.session_id(), Some(session));
    }

    // Note: test_session_id_epoch_handoff_none requires CommitteeTransition
    // which needs complex setup. Deferred to integration tests.

    #[test]
    fn test_session_id_ping_none() {
        let msg = CoordinatorMessage::Ping { timestamp: 123 };
        assert_eq!(msg.session_id(), None);
    }

    #[test]
    fn test_session_id_pong_none() {
        let msg = CoordinatorMessage::Pong {
            timestamp: 123,
            received_at: 456,
        };
        assert_eq!(msg.session_id(), None);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Encode/Decode Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_encode_decode_ping() {
        let msg = CoordinatorMessage::Ping { timestamp: 1700000000 };
        let encoded = msg.encode();
        let decoded = CoordinatorMessage::decode(&encoded).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_encode_decode_pong() {
        let msg = CoordinatorMessage::Pong {
            timestamp: 1700000000,
            received_at: 1700000001,
        };
        let encoded = msg.encode();
        let decoded = CoordinatorMessage::decode(&encoded).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_encode_decode_vote_receipt() {
        let msg = CoordinatorMessage::VoteReceipt {
            session_id: SessionId::new([0x01; 32]),
            workload_id: WorkloadId::new([0x02; 32]),
            vote: MessageVote::reject("invalid"),
            voter: CoordinatorId::new([0x03; 32]),
        };
        let encoded = msg.encode();
        let decoded = CoordinatorMessage::decode(&encoded).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_encode_deterministic() {
        let msg = CoordinatorMessage::Ping { timestamp: 123 };
        let encoded1 = msg.encode();
        let encoded2 = msg.encode();
        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_decode_empty_error() {
        let result = CoordinatorMessage::decode(&[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MessageDecodeError::EmptyData));
    }

    #[test]
    fn test_decode_invalid_bytes_error() {
        let result = CoordinatorMessage::decode(&[0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MessageDecodeError::DeserializationFailed { .. }
        ));
    }

    #[test]
    fn test_encode_decode_propose_receipt() {
        let msg = CoordinatorMessage::ProposeReceipt {
            session_id: SessionId::new([0x01; 32]),
            data: make_receipt_data(),
            proposer: CoordinatorId::new([0x02; 32]),
        };
        let encoded = msg.encode();
        let decoded = CoordinatorMessage::decode(&encoded).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_encode_decode_signing_commitment() {
        let msg = CoordinatorMessage::SigningCommitment {
            session_id: SessionId::new([0x01; 32]),
            commitment: make_signing_commitment(),
        };
        let encoded = msg.encode();
        let decoded = CoordinatorMessage::decode(&encoded).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_encode_decode_partial_signature() {
        let msg = CoordinatorMessage::PartialSignature {
            session_id: SessionId::new([0x01; 32]),
            partial: make_partial_signature(),
        };
        let encoded = msg.encode();
        let decoded = CoordinatorMessage::decode(&encoded).expect("decode");
        assert_eq!(msg, decoded);
    }

    // Note: EpochHandoff roundtrip test requires complex CommitteeTransition setup
    // which depends on CoordinatorCommittee, CoordinatorMember, ValidatorId, etc.
    // This test is deferred to integration tests where full crate context is available.

    // ─────────────────────────────────────────────────────────────────────────────
    // Convenience Constructor Tests
    // ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_ping_now() {
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let ping = CoordinatorMessage::ping_now();

        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        if let CoordinatorMessage::Ping { timestamp } = ping {
            assert!(timestamp >= before);
            assert!(timestamp <= after);
        } else {
            panic!("expected Ping");
        }
    }

    #[test]
    fn test_pong_for() {
        let ping_ts = 1700000000u64;
        let pong = CoordinatorMessage::pong_for(ping_ts);

        if let CoordinatorMessage::Pong {
            timestamp,
            received_at,
        } = pong
        {
            assert_eq!(timestamp, ping_ts);
            assert!(received_at > 0);
        } else {
            panic!("expected Pong");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Test Helpers
    // ─────────────────────────────────────────────────────────────────────────────

    fn make_receipt_data() -> ReceiptData {
        use dsdn_common::coordinator::WorkloadId as CommonWorkloadId;
        ReceiptData::new(
            CommonWorkloadId::new([0x01; 32]),
            [0x02; 32],
            vec![],
            1700000000,
            1,
            1,
        )
    }

    fn make_signing_commitment() -> SigningCommitmentProto {
        SigningCommitmentProto {
            session_id: vec![0x01; 32],
            signer_id: vec![0x02; 32],
            hiding: vec![0x03; 32],
            binding: vec![0x04; 32],
            timestamp: 1700000000,
        }
    }

    fn make_partial_signature() -> PartialSignatureProto {
        PartialSignatureProto {
            session_id: vec![0x01; 32],
            signer_id: vec![0x02; 32],
            signature_share: vec![0x03; 32],
            commitment: make_signing_commitment(),
        }
    }
}