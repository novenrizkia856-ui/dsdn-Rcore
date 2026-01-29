//! # TSS Protocol Messages
//!
//! Module ini menyediakan types dan definisi untuk Threshold Signature Scheme (TSS)
//! protocol messages dalam sistem DSDN.
//!
//! ## Architecture Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────────┐
//! │                        TSS Protocol Architecture                                │
//! └─────────────────────────────────────────────────────────────────────────────────┘
//!
//!                           ┌──────────────────────┐
//!                           │  Coordinator Nodes   │
//!                           │  (TSS Participants)  │
//!                           └──────────┬───────────┘
//!                                      │
//!              ┌───────────────────────┼───────────────────────┐
//!              │                       │                       │
//!              ▼                       ▼                       ▼
//!     ┌────────────────┐     ┌────────────────┐     ┌────────────────┐
//!     │      DKG       │     │    Signing     │     │   Committee    │
//!     │   (Phase 1)    │────▶│   (Phase 2)    │────▶│  Coordination  │
//!     └────────┬───────┘     └────────┬───────┘     └────────┬───────┘
//!              │                      │                      │
//!              ▼                      ▼                      ▼
//!     ┌────────────────┐     ┌────────────────┐     ┌────────────────┐
//!     │  Round1Package │     │ SigningRequest │     │CoordinatorMember│
//!     │  Round2Package │     │   Commitment   │     │CoordinatorComm. │
//!     │   DKGResult    │     │  PartialSig    │     │  ReceiptData   │
//!     └────────────────┘     │  AggregateSig  │     │ThresholdReceipt│
//!                            └────────────────┘     └────────────────┘
//!                                      │                      │
//!                                      └──────────┬───────────┘
//!                                                 │
//!                                                 ▼
//!                                      ┌────────────────────┐
//!                                      │   Proto Encoding   │
//!                                      │  (bincode + SHA3)  │
//!                                      └────────────────────┘
//! ```
//!
//! ## Message Flow Diagrams
//!
//! ### DKG Flow (Distributed Key Generation)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        DKG Protocol Flow                        │
//! └─────────────────────────────────────────────────────────────────┘
//!
//!   Participant A          Coordinator          Participant B
//!        │                      │                      │
//!        │──DKGRound1Package───▶│                      │
//!        │                      │◀──DKGRound1Package───│
//!        │                      │                      │
//!        │◀──Broadcast Round1───│───Broadcast Round1──▶│
//!        │                      │                      │
//!        │──DKGRound2Package───▶│                      │
//!        │   (per-participant)  │◀──DKGRound2Package───│
//!        │                      │                      │
//!        │◀──Deliver Round2─────│─────Deliver Round2──▶│
//!        │                      │                      │
//!        │──────DKGResult──────▶│                      │
//!        │                      │◀──────DKGResult──────│
//!        │                      │                      │
//!        │◀──GroupPublicKey─────│────GroupPublicKey───▶│
//!        │                      │                      │
//!
//!   Round1: Commitments + proofs (broadcast)
//!   Round2: Encrypted shares (peer-to-peer)
//!   Result: Group public key + individual keys
//! ```
//!
//! ### Signing Flow (Threshold Signing)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     Threshold Signing Flow                      │
//! └─────────────────────────────────────────────────────────────────┘
//!
//!   Client              Coordinator              Participants
//!      │                      │                      │
//!      │──SigningRequest─────▶│                      │
//!      │   (message_hash)     │───SigningRequest────▶│
//!      │                      │                      │
//!      │                      │◀──SigningCommitment──│
//!      │                      │   (hiding, binding)  │
//!      │                      │                      │
//!      │                      │──Broadcast Commits──▶│
//!      │                      │                      │
//!      │                      │◀──PartialSignature───│
//!      │                      │   (signature_share)  │
//!      │                      │                      │
//!      │◀─AggregateSignature──│                      │
//!      │   (FROST signature)  │                      │
//!      │                      │                      │
//!
//!   1. Client submits signing request
//!   2. Participants generate commitments (nonces)
//!   3. Participants compute partial signatures
//!   4. Coordinator aggregates into FROST signature
//! ```
//!
//! ### Receipt Flow (Committee Coordination)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      Receipt Signing Flow                       │
//! └─────────────────────────────────────────────────────────────────┘
//!
//!   Storage Node          Committee              Verifier
//!        │                    │                      │
//!        │──ReceiptData──────▶│                      │
//!        │  (workload_id,     │                      │
//!        │   blob_hash,       │                      │
//!        │   placement)       │                      │
//!        │                    │                      │
//!        │                    │──[Threshold Sign]───▶│
//!        │                    │                      │
//!        │◀─ThresholdReceipt──│                      │
//!        │  (aggregate_sig,   │                      │
//!        │   signer_ids,      │                      │
//!        │   committee_hash)  │                      │
//!        │                    │                      │
//!        │                    │                      │
//!        │────────────────────│──ThresholdReceipt───▶│
//!        │                    │                      │──verify()
//!        │                    │                      │
//!
//!   1. Storage node creates receipt data
//!   2. Committee threshold-signs the receipt
//!   3. Verifier validates signature against committee
//! ```
//!
//! ## Encoding Specification
//!
//! ### Encoding Format Table
//!
//! | Message Type | Encoding | Endianness | Hash Algorithm | Deterministic |
//! |--------------|----------|------------|----------------|---------------|
//! | `DKGRound1PackageProto` | bincode | Little-endian | SHA3-256 | Yes |
//! | `DKGRound2PackageProto` | bincode | Little-endian | N/A | Yes |
//! | `DKGResultProto` | bincode | Little-endian | N/A | Yes |
//! | `SigningRequestProto` | bincode | Little-endian | N/A | Yes |
//! | `SigningCommitmentProto` | bincode | Little-endian | N/A | Yes |
//! | `PartialSignatureProto` | bincode | Little-endian | N/A | Yes |
//! | `AggregateSignatureProto` | bincode | Little-endian | SHA3-256 | Yes |
//! | `CoordinatorMemberProto` | bincode | Little-endian | N/A | Yes |
//! | `CoordinatorCommitteeProto` | bincode | Little-endian | SHA3-256 | Yes |
//! | `ReceiptDataProto` | bincode | Little-endian | SHA3-256 | Yes |
//! | `ThresholdReceiptProto` | bincode | Little-endian | SHA3-256 | Yes |
//!
//! ### Field Size Constants
//!
//! | Constant | Value | Used By |
//! |----------|-------|---------|
//! | `SESSION_ID_SIZE` | 32 | DKG |
//! | `PARTICIPANT_ID_SIZE` | 32 | DKG |
//! | `COMMITMENT_SIZE` | 32 | DKG |
//! | `PROOF_SIZE` | 64 | DKG |
//! | `GROUP_PUBKEY_SIZE` | 32 | DKG, Committee |
//! | `SIGNER_ID_SIZE` | 32 | Signing |
//! | `MESSAGE_HASH_SIZE` | 32 | Signing |
//! | `HIDING_SIZE` | 32 | Signing |
//! | `BINDING_SIZE` | 32 | Signing |
//! | `SIGNATURE_SHARE_SIZE` | 32 | Signing |
//! | `FROST_SIGNATURE_SIZE` | 64 | Signing |
//! | `COORDINATOR_ID_SIZE` | 32 | Committee |
//! | `VALIDATOR_ID_SIZE` | 32 | Committee |
//! | `PUBKEY_SIZE` | 32 | Committee |
//! | `WORKLOAD_ID_SIZE` | 32 | Receipt |
//! | `BLOB_HASH_SIZE` | 32 | Receipt |
//! | `NODE_ID_SIZE` | 32 | Receipt |
//! | `COMMITTEE_HASH_SIZE` | 32 | Receipt |
//!
//! ### Encoding Functions
//!
//! | Function | Input | Output |
//! |----------|-------|--------|
//! | `encode_dkg_round1` | `&DKGRound1PackageProto` | `Vec<u8>` |
//! | `decode_dkg_round1` | `&[u8]` | `Result<DKGRound1PackageProto, DecodeError>` |
//! | `encode_dkg_round2` | `&DKGRound2PackageProto` | `Vec<u8>` |
//! | `decode_dkg_round2` | `&[u8]` | `Result<DKGRound2PackageProto, DecodeError>` |
//! | `encode_dkg_result` | `&DKGResultProto` | `Vec<u8>` |
//! | `decode_dkg_result` | `&[u8]` | `Result<DKGResultProto, DecodeError>` |
//! | `encode_signing_request` | `&SigningRequestProto` | `Vec<u8>` |
//! | `decode_signing_request` | `&[u8]` | `Result<SigningRequestProto, SigningDecodeError>` |
//! | `encode_signing_commitment` | `&SigningCommitmentProto` | `Vec<u8>` |
//! | `decode_signing_commitment` | `&[u8]` | `Result<SigningCommitmentProto, SigningDecodeError>` |
//! | `encode_partial_signature` | `&PartialSignatureProto` | `Vec<u8>` |
//! | `decode_partial_signature` | `&[u8]` | `Result<PartialSignatureProto, SigningDecodeError>` |
//! | `encode_aggregate_signature` | `&AggregateSignatureProto` | `Vec<u8>` |
//! | `decode_aggregate_signature` | `&[u8]` | `Result<AggregateSignatureProto, SigningDecodeError>` |
//! | `encode_committee` | `&CoordinatorCommitteeProto` | `Vec<u8>` |
//! | `decode_committee` | `&[u8]` | `Result<CoordinatorCommitteeProto, CommitteeDecodeError>` |
//! | `encode_receipt` | `&ThresholdReceiptProto` | `Vec<u8>` |
//! | `decode_receipt` | `&[u8]` | `Result<ThresholdReceiptProto, CommitteeDecodeError>` |
//!
//! ### Hash Functions
//!
//! | Function | Input | Output | Algorithm |
//! |----------|-------|--------|-----------|
//! | `compute_dkg_round1_hash` | `&DKGRound1PackageProto` | `[u8; 32]` | SHA3-256 |
//! | `compute_aggregate_signature_hash` | `&AggregateSignatureProto` | `[u8; 32]` | SHA3-256 |
//! | `compute_committee_hash` | `&CoordinatorCommitteeProto` | `[u8; 32]` | SHA3-256 |
//! | `compute_receipt_hash` | `&ThresholdReceiptProto` | `[u8; 32]` | SHA3-256 |
//! | `ReceiptDataProto::compute_hash` | `&self` | `[u8; 32]` | SHA3-256 |
//!
//! ## Encoding Consistency
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Encoding Consistency                         │
//! └─────────────────────────────────────────────────────────────────┘
//!
//!   DAEvent                          TSS Proto Messages
//!      │                                  │
//!      ▼                                  ▼
//! encode_event()                  encode_dkg_round1()
//!      │                          encode_signing_request()
//!      │    ┌──────────────────┐  encode_committee()
//!      └───▶│  Same bincode    │◀─encode_receipt()
//!           │  Same byte order │
//!           │  Same field enc. │
//!           └──────────────────┘
//!                    │
//!                    ▼
//!           ┌──────────────────┐
//!           │    SHA3-256      │
//!           │  Deterministic   │
//!           │    Hashing       │
//!           └──────────────────┘
//! ```
//!
//! ## Usage Examples
//!
//! ### DKG Round 1 Example
//!
//! ```rust,ignore
//! use dsdn_proto::tss::{
//!     DKGRound1PackageProto,
//!     encode_dkg_round1,
//!     decode_dkg_round1,
//!     compute_dkg_round1_hash,
//! };
//!
//! // Create a DKG Round 1 package
//! let package = DKGRound1PackageProto {
//!     session_id: vec![0x01; 32],
//!     participant_id: vec![0x02; 32],
//!     commitment: vec![0x03; 32],
//!     proof: vec![0x04; 64],
//!     epoch: 1,
//! };
//!
//! // Validate
//! package.validate().expect("valid package");
//!
//! // Encode to bytes
//! let bytes = encode_dkg_round1(&package);
//!
//! // Decode back
//! let decoded = decode_dkg_round1(&bytes).expect("decode success");
//! assert_eq!(package, decoded);
//!
//! // Compute hash
//! let hash = compute_dkg_round1_hash(&package);
//! ```
//!
//! ### Signing Request Example
//!
//! ```rust,ignore
//! use dsdn_proto::tss::{
//!     SigningRequestProto,
//!     encode_signing_request,
//!     decode_signing_request,
//! };
//!
//! // Create a signing request
//! let request = SigningRequestProto {
//!     session_id: vec![0x01; 32],
//!     message: b"Hello, World!".to_vec(),
//!     message_hash: vec![0x02; 32],
//!     required_signers: vec![vec![0x03; 32], vec![0x04; 32]],
//!     epoch: 1,
//!     timeout_secs: 30,
//!     request_timestamp: 1700000000,
//! };
//!
//! // Validate
//! request.validate().expect("valid request");
//!
//! // Encode/decode roundtrip
//! let bytes = encode_signing_request(&request);
//! let decoded = decode_signing_request(&bytes).expect("decode success");
//! ```
//!
//! ### Threshold Receipt Example
//!
//! ```rust,ignore
//! use dsdn_proto::tss::{
//!     ReceiptDataProto,
//!     ThresholdReceiptProto,
//!     AggregateSignatureProto,
//!     encode_receipt,
//!     decode_receipt,
//!     compute_receipt_hash,
//! };
//!
//! // Create receipt data
//! let receipt_data = ReceiptDataProto {
//!     workload_id: vec![0x01; 32],
//!     blob_hash: vec![0x02; 32],
//!     placement: vec![vec![0x03; 32]],
//!     timestamp: 1700000000,
//!     sequence: 1,
//!     epoch: 1,
//! };
//!
//! // Create aggregate signature
//! let signature = AggregateSignatureProto {
//!     signature: vec![0xAA; 64],
//!     signer_ids: vec![vec![0x01; 32], vec![0x02; 32]],
//!     message_hash: vec![0xBB; 32],
//!     aggregated_at: 1700000000,
//! };
//!
//! // Create threshold receipt
//! let receipt = ThresholdReceiptProto {
//!     receipt_data,
//!     signature,
//!     signer_ids: vec![vec![0x01; 32], vec![0x02; 32]],
//!     epoch: 1,
//!     committee_hash: vec![0xCC; 32],
//! };
//!
//! // Validate
//! receipt.validate().expect("valid receipt");
//!
//! // Encode/decode roundtrip
//! let bytes = encode_receipt(&receipt);
//! let decoded = decode_receipt(&bytes).expect("decode success");
//!
//! // Compute hash
//! let hash = compute_receipt_hash(&receipt);
//! ```
//!
//! ## Submodules
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`types`] | Basic wrapper types untuk bytes dan signatures |
//! | [`dkg`] | DKG protocol message types (Round1, Round2, Result) |
//! | [`signing`] | Threshold signing message types (Request, Commitment, Partial, Aggregate) |
//! | [`committee`] | Committee coordination message types (Member, Committee, Receipt) |
//!
//! ## Version Compatibility
//!
//! ### Current Version: 0.1
//!
//! ### Stability Guarantees
//!
//! | Property | Guarantee |
//! |----------|-----------|
//! | Encoding format | Stable (bincode little-endian) |
//! | Hash algorithm | Stable (SHA3-256) |
//! | Field order | Stable (must not change) |
//! | Field sizes | Stable (constants defined) |
//!
//! ### Breaking Changes
//!
//! The following changes would be BREAKING and require version bump:
//! - Changing field order in any proto struct
//! - Changing encoding format or byte order
//! - Changing hash algorithm
//! - Removing or renaming public types
//!
//! ### Non-Breaking Changes
//!
//! The following changes are safe:
//! - Adding new proto types
//! - Adding new optional fields (with defaults)
//! - Adding new validation rules (stricter)
//! - Adding new error variants

pub mod types;
pub mod dkg;
pub mod signing;
pub mod committee;

#[cfg(test)]
mod tests;

// ════════════════════════════════════════════════════════════════════════════════
// RE-EXPORTS: WRAPPER TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// Re-export wrapper types from types module.
pub use types::{BytesWrapper, SignatureBytes};

/// Re-export size constants from types module.
pub use types::{BYTES_WRAPPER_SIZE, SIGNATURE_BYTES_SIZE};

// ════════════════════════════════════════════════════════════════════════════════
// RE-EXPORTS: DKG MESSAGES
// ════════════════════════════════════════════════════════════════════════════════

/// Re-export DKG proto messages.
pub use dkg::{
    DKGRound1PackageProto,
    DKGRound2PackageProto,
    DKGResultProto,
};

/// Re-export DKG encoding functions.
pub use dkg::{
    encode_dkg_round1,
    decode_dkg_round1,
    compute_dkg_round1_hash,
    encode_dkg_round2,
    decode_dkg_round2,
    encode_dkg_result,
    decode_dkg_result,
};

/// Re-export DKG error types.
pub use dkg::{ValidationError, DecodeError};

/// Re-export DKG size constants.
pub use dkg::{
    SESSION_ID_SIZE,
    PARTICIPANT_ID_SIZE,
    COMMITMENT_SIZE,
    PROOF_SIZE,
    GROUP_PUBKEY_SIZE,
};

// ════════════════════════════════════════════════════════════════════════════════
// RE-EXPORTS: SIGNING MESSAGES
// ════════════════════════════════════════════════════════════════════════════════

/// Re-export signing proto messages.
pub use signing::{
    SigningRequestProto,
    SigningCommitmentProto,
    PartialSignatureProto,
    AggregateSignatureProto,
};

/// Re-export signing encoding functions.
pub use signing::{
    encode_signing_request,
    decode_signing_request,
    encode_signing_commitment,
    decode_signing_commitment,
    encode_partial_signature,
    decode_partial_signature,
    encode_aggregate_signature,
    decode_aggregate_signature,
    compute_aggregate_signature_hash,
};

/// Re-export signing error types.
pub use signing::{SigningValidationError, SigningDecodeError};

/// Re-export signing size constants.
pub use signing::{
    SIGNER_ID_SIZE,
    MESSAGE_HASH_SIZE,
    HIDING_SIZE,
    BINDING_SIZE,
    SIGNATURE_SHARE_SIZE,
    FROST_SIGNATURE_SIZE,
};

// ════════════════════════════════════════════════════════════════════════════════
// RE-EXPORTS: COMMITTEE MESSAGES
// ════════════════════════════════════════════════════════════════════════════════

/// Re-export committee proto messages.
pub use committee::{
    CoordinatorMemberProto,
    CoordinatorCommitteeProto,
};

/// Re-export committee encoding functions.
pub use committee::{
    encode_committee,
    decode_committee,
    compute_committee_hash,
};

/// Re-export committee error types.
pub use committee::{CommitteeValidationError, CommitteeDecodeError};

/// Re-export committee size constants.
pub use committee::{
    COORDINATOR_ID_SIZE,
    VALIDATOR_ID_SIZE,
    PUBKEY_SIZE,
};

// ════════════════════════════════════════════════════════════════════════════════
// RE-EXPORTS: RECEIPT MESSAGES
// ════════════════════════════════════════════════════════════════════════════════

/// Re-export receipt proto messages.
pub use committee::{
    ReceiptDataProto,
    ThresholdReceiptProto,
};

/// Re-export receipt encoding functions.
pub use committee::{
    encode_receipt,
    decode_receipt,
    compute_receipt_hash,
};

/// Re-export receipt size constants.
pub use committee::{
    WORKLOAD_ID_SIZE,
    BLOB_HASH_SIZE,
    NODE_ID_SIZE,
    COMMITTEE_HASH_SIZE,
};