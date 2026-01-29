//! # TSS Protocol Messages
//!
//! Module ini menyediakan types dan definisi untuk Threshold Signature Scheme (TSS)
//! protocol messages dalam sistem DSDN.
//!
//! ## Overview
//!
//! TSS module menyediakan structure untuk:
//! - DKG messages (Distributed Key Generation)
//! - Threshold signing messages
//! - Committee coordination messages
//!
//! ## Message Categories
//!
//! | Category | Messages |
//! |----------|----------|
//! | DKG | Round1Package, Round2Package, DKGResult |
//! | Signing | SigningRequest, Commitment, PartialSig, AggregateSig |
//! | Committee | CommitteeProto, MemberProto, ReceiptProto |
//!
//! ## Encoding
//!
//! Semua TSS protocol messages menggunakan encoding yang konsisten dengan
//! proto crate lainnya:
//!
//! | Property | Value |
//! |----------|-------|
//! | Format | bincode |
//! | Byte Order | Little-endian |
//! | Serialization | Deterministic |
//!
//! ## Current Status
//!
//! Saat ini module menyediakan:
//! - Wrapper types untuk raw bytes (`BytesWrapper`, `SignatureBytes`)
//! - DKG Round 1 proto message (`DKGRound1PackageProto`)
//! - DKG Round 2 proto message (`DKGRound2PackageProto`)
//! - DKG Result proto message (`DKGResultProto`)
//! - Signing Request proto message (`SigningRequestProto`)
//! - Signing Commitment proto message (`SigningCommitmentProto`)
//! - Partial Signature proto message (`PartialSignatureProto`)
//! - Aggregate Signature proto message (`AggregateSignatureProto`)
//! - Coordinator Member proto message (`CoordinatorMemberProto`)
//! - Coordinator Committee proto message (`CoordinatorCommitteeProto`)
//! - Receipt Data proto message (`ReceiptDataProto`)
//! - Threshold Receipt proto message (`ThresholdReceiptProto`)
//!
//! ## Submodules
//!
//! | Module | Description |
//! |--------|-------------|
//! | `types` | Basic wrapper types untuk bytes dan signatures |
//! | `dkg` | DKG protocol message types |
//! | `signing` | Threshold signing message types |
//! | `committee` | Committee coordination message types |

pub mod types;
pub mod dkg;
pub mod signing;
pub mod committee;

// Re-export wrapper types
pub use types::{BytesWrapper, SignatureBytes};

// Re-export size constants
pub use types::{BYTES_WRAPPER_SIZE, SIGNATURE_BYTES_SIZE};

// Re-export DKG Round 1 types
pub use dkg::{
    DKGRound1PackageProto,
    encode_dkg_round1,
    decode_dkg_round1,
    compute_dkg_round1_hash,
};

// Re-export DKG Round 2 types
pub use dkg::{
    DKGRound2PackageProto,
    encode_dkg_round2,
    decode_dkg_round2,
};

// Re-export DKG Result types
pub use dkg::{
    DKGResultProto,
    encode_dkg_result,
    decode_dkg_result,
};

// Re-export DKG error types
pub use dkg::{ValidationError, DecodeError};

// Re-export DKG size constants
pub use dkg::{
    SESSION_ID_SIZE,
    PARTICIPANT_ID_SIZE,
    COMMITMENT_SIZE,
    PROOF_SIZE,
    GROUP_PUBKEY_SIZE,
};

// Re-export Signing Request types
pub use signing::{
    SigningRequestProto,
    encode_signing_request,
    decode_signing_request,
};

// Re-export Signing Commitment types
pub use signing::{
    SigningCommitmentProto,
    encode_signing_commitment,
    decode_signing_commitment,
};

// Re-export Partial Signature types
pub use signing::{
    PartialSignatureProto,
    encode_partial_signature,
    decode_partial_signature,
};

// Re-export Aggregate Signature types
pub use signing::{
    AggregateSignatureProto,
    encode_aggregate_signature,
    decode_aggregate_signature,
    compute_aggregate_signature_hash,
};

// Re-export Signing error types
pub use signing::{SigningValidationError, SigningDecodeError};

// Re-export Signing size constants
pub use signing::{
    SIGNER_ID_SIZE,
    MESSAGE_HASH_SIZE,
    HIDING_SIZE,
    BINDING_SIZE,
    SIGNATURE_SHARE_SIZE,
    FROST_SIGNATURE_SIZE,
};

// Re-export Committee types
pub use committee::{
    CoordinatorMemberProto,
    CoordinatorCommitteeProto,
    encode_committee,
    decode_committee,
    compute_committee_hash,
};

// Re-export Committee error types
pub use committee::{CommitteeValidationError, CommitteeDecodeError};

// Re-export Committee size constants
pub use committee::{
    COORDINATOR_ID_SIZE,
    VALIDATOR_ID_SIZE,
    PUBKEY_SIZE,
};

// Re-export Receipt types
pub use committee::{
    ReceiptDataProto,
    ThresholdReceiptProto,
    encode_receipt,
    decode_receipt,
    compute_receipt_hash,
};

// Re-export Receipt size constants
pub use committee::{
    WORKLOAD_ID_SIZE,
    BLOB_HASH_SIZE,
    NODE_ID_SIZE,
    COMMITTEE_HASH_SIZE,
};