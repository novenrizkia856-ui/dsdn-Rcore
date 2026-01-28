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
//!
//! ## Submodules
//!
//! | Module | Description |
//! |--------|-------------|
//! | `types` | Basic wrapper types untuk bytes dan signatures |
//! | `dkg` | DKG protocol message types |

pub mod types;
pub mod dkg;

// Re-export wrapper types
pub use types::{BytesWrapper, SignatureBytes};

// Re-export size constants
pub use types::{BYTES_WRAPPER_SIZE, SIGNATURE_BYTES_SIZE};

// Re-export DKG types
pub use dkg::{
    DKGRound1PackageProto,
    ValidationError,
    DecodeError,
    encode_dkg_round1,
    decode_dkg_round1,
    compute_dkg_round1_hash,
    // Size constants
    SESSION_ID_SIZE,
    PARTICIPANT_ID_SIZE,
    COMMITMENT_SIZE,
    PROOF_SIZE,
};