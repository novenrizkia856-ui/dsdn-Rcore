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
//!
//! ## Submodules
//!
//! | Module | Description |
//! |--------|-------------|
//! | `types` | Basic wrapper types untuk bytes dan signatures |
//! | `dkg` | DKG protocol message types |
//! | `signing` | Threshold signing message types |

pub mod types;
pub mod dkg;
pub mod signing;

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

// Re-export Signing types
pub use signing::{
    SigningRequestProto,
    encode_signing_request,
    decode_signing_request,
};

// Re-export Signing error types
pub use signing::{SigningValidationError, SigningDecodeError};

// Re-export Signing size constants
pub use signing::{
    SIGNER_ID_SIZE,
    MESSAGE_HASH_SIZE,
};