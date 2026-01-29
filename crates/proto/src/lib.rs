//! # DSDN Proto Crate
//!
//! Proto crate adalah definisi schema resmi untuk Data Availability (DA) events
//! dan fallback-related types dalam sistem DSDN (Distributed Storage and Data Network).
//!
//! ## Module Overview
//!
//! Crate ini menyediakan:
//! - Definisi event types untuk komunikasi dengan Celestia DA layer
//! - Deterministic serialization untuk konsensus dan verifikasi
//! - Health status dan error types untuk monitoring DA layer
//! - Encoding helpers untuk serialization dan hashing
//! - Fallback event types untuk DA resilience (14A.1A)
//! - Reconciliation dan consistency verification types
//!
//! Proto crate adalah kontrak data antara komponen DSDN:
//! - **Coordinator**: Membuat dan mengirim events ke DA layer
//! - **Storage Nodes**: Menerima dan memproses events dari DA layer
//! - **Validators**: Memverifikasi events dan state transitions
//!
//! ## Modules
//!
//! - [`da_event`]: DAEvent enum dan semua event struct types
//! - [`da_health`]: DAHealthStatus dan DAError types
//! - [`encoding`]: Serialization helpers untuk deterministic encoding dan hashing
//! - [`fallback_event`]: FallbackEvent enum dan related structs untuk DA fallback operations
//! - [`pending_blob`]: PendingBlob struct untuk blobs menunggu reconciliation
//! - [`reconcile_report`]: ReconcileReport dan related types untuk hasil reconciliation
//! - [`consistency_report`]: ConsistencyReport dan related types untuk verifikasi konsistensi
//! - [`tss`]: TSS protocol message types untuk threshold signing
//!
//! ## Architecture Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                           DSDN Proto Architecture                           │
//! └─────────────────────────────────────────────────────────────────────────────┘
//!
//!                              ┌─────────────────┐
//!                              │   Celestia DA   │
//!                              │  (Primary DA)   │
//!                              └────────┬────────┘
//!                                       │
//!                    ┌──────────────────┼──────────────────┐
//!                    │                  │                  │
//!                    ▼                  ▼                  ▼
//!           ┌────────────────┐ ┌────────────────┐ ┌────────────────┐
//!           │   DAEvent      │ │ FallbackEvent  │ │   Encoding     │
//!           │ (Normal Ops)   │ │ (Resilience)   │ │   & Hashing    │
//!           └────────┬───────┘ └────────┬───────┘ └────────┬───────┘
//!                    │                  │                  │
//!                    │                  │                  │
//!                    ▼                  ▼                  ▼
//!           ┌────────────────────────────────────────────────────────┐
//!           │                  Deterministic Layer                   │
//!           │  ┌──────────┐  ┌──────────┐  ┌──────────┐             │
//!           │  │ bincode  │  │ SHA3-256 │  │ Roundtrip│             │
//!           │  │ encoding │→ │  hashing │→ │  verify  │             │
//!           │  └──────────┘  └──────────┘  └──────────┘             │
//!           └────────────────────────────────────────────────────────┘
//!                    │                  │                  │
//!                    ▼                  ▼                  ▼
//!           ┌────────────────┐ ┌────────────────┐ ┌────────────────┐
//!           │  PendingBlob   │ │ReconcileReport │ │ConsistencyRpt  │
//!           │(Pending Data)  │ │(Reconciliation)│ │(Verification)  │
//!           └────────────────┘ └────────────────┘ └────────────────┘
//! ```
//!
//! ## Fallback Event Lifecycle
//!
//! Berikut adalah lifecycle lengkap fallback events dalam sistem DSDN:
//!
//! ### 1. Normal Operation (Kondisi Awal)
//!
//! Sistem beroperasi dengan Celestia sebagai primary DA layer.
//! Semua DAEvents di-post dan di-retrieve dari Celestia.
//!
//! ### 2. Fallback Activation
//!
//! Ketika Celestia tidak tersedia (timeout, unreachable, atau error):
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Fallback Activation Flow                     │
//! └─────────────────────────────────────────────────────────────────┘
//!
//!   Celestia Unavailable
//!           │
//!           ▼
//!   ┌───────────────────┐
//!   │ Detect Condition  │ ← Timeout / Connection Error / Quorum Decision
//!   └─────────┬─────────┘
//!             │
//!             ▼
//!   ┌───────────────────┐
//!   │FallbackActivated  │ ← Event di-emit dengan:
//!   │      Event        │   - reason: String (alasan aktivasi)
//!   └─────────┬─────────┘   - celestia_last_height: u64 (height terakhir)
//!             │             - activated_at: u64 (Unix timestamp)
//!             │             - fallback_type: FallbackType
//!             ▼
//!   ┌───────────────────┐
//!   │  Fallback DA      │ ← ValidatorQuorum atau Emergency
//!   │   Active          │
//!   └───────────────────┘
//! ```
//!
//! ### 3. Operation During Fallback
//!
//! Selama fallback aktif:
//! - Blobs disimpan ke fallback DA layer
//! - Setiap blob direkam sebagai `PendingBlob`
//! - `PendingBlob` menyimpan: data, sequence, source_da, timestamp, retry_count
//!
//! ### 4. Recovery & Reconciliation
//!
//! Ketika Celestia kembali tersedia:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                   Reconciliation Process                        │
//! └─────────────────────────────────────────────────────────────────┘
//!
//!   Celestia Recovers
//!           │
//!           ▼
//!   ┌───────────────────┐
//!   │ReconciliationStart│ ← Event di-emit dengan:
//!   │      Event        │   - pending_count: u64
//!   └─────────┬─────────┘   - started_at: u64
//!             │             - source_da: String
//!             ▼
//!   ┌───────────────────┐
//!   │  Process Each     │ ← Untuk setiap PendingBlob:
//!   │  PendingBlob      │   1. Encode blob
//!   └─────────┬─────────┘   2. Post ke Celestia
//!             │             3. Record hasil di ReconcileDetail
//!             ▼
//!   ┌───────────────────┐
//!   │ReconciliationEnd  │ ← Event di-emit dengan:
//!   │      Event        │   - reconciled_count: u64
//!   └─────────┬─────────┘   - failed_count: u64
//!             │             - completed_at: u64
//!             │             - duration_ms: u64
//!             ▼
//!   ┌───────────────────┐
//!   │  ReconcileReport  │ ← Summary lengkap dengan details per-blob
//!   └───────────────────┘
//! ```
//!
//! ### 5. Fallback Deactivation
//!
//! Setelah reconciliation selesai:
//!
//! ```text
//!   ┌───────────────────┐
//!   │FallbackDeactivated│ ← Event di-emit dengan:
//!   │      Event        │   - celestia_recovery_height: u64
//!   └─────────┬─────────┘   - blobs_reconciled: u64
//!             │             - deactivated_at: u64
//!             │             - downtime_duration_secs: u64
//!             ▼
//!   ┌───────────────────┐
//!   │  Normal Operation │ ← Kembali ke Celestia sebagai primary DA
//!   └───────────────────┘
//! ```
//!
//! ### 6. Consistency Verification
//!
//! Setelah deactivation, sistem dapat melakukan verifikasi:
//!
//! ```text
//!   ┌───────────────────┐
//!   │ ConsistencyReport │ ← Hasil verifikasi dengan:
//!   │                   │   - celestia_height: u64
//!   └─────────┬─────────┘   - fallback_height: u64
//!             │             - is_consistent: bool
//!             │             - mismatches: Vec<ConsistencyMismatch>
//!             ▼
//!   ┌───────────────────┐
//!   │  MismatchType     │ ← Missing | HashMismatch | SequenceGap | Duplicate
//!   └───────────────────┘
//! ```
//!
//! ## Serialization Format for Fallback Types
//!
//! ### Deterministic Encoding
//!
//! Semua fallback-related types menggunakan encoding yang IDENTIK dengan DA events:
//!
//! | Property | Value |
//! |----------|-------|
//! | Format | bincode |
//! | Byte Order | Little-endian |
//! | Integer Encoding | Fixed-width |
//! | String Encoding | Length-prefixed (u64) |
//! | Enum Encoding | u32 discriminant + payload |
//!
//! ### Encoding Functions
//!
//! | Function | Input | Output |
//! |----------|-------|--------|
//! | `encode_fallback_event` | `&FallbackEvent` | `Vec<u8>` |
//! | `decode_fallback_event` | `&[u8]` | `Result<FallbackEvent, DecodeError>` |
//! | `encode_pending_blob` | `&PendingBlob` | `Vec<u8>` |
//! | `decode_pending_blob` | `&[u8]` | `Result<PendingBlob, DecodeError>` |
//!
//! ### Hash Computation
//!
//! Hash untuk fallback types dihitung dengan pipeline yang sama:
//!
//! ```text
//! ┌──────────┐     ┌──────────┐     ┌──────────┐
//! │  Struct  │ ──▶ │  encode  │ ──▶ │ SHA3-256 │ ──▶ [u8; 32]
//! └──────────┘     └──────────┘     └──────────┘
//! ```
//!
//! | Function | Input | Output |
//! |----------|-------|--------|
//! | `compute_fallback_event_hash` | `&FallbackEvent` | `[u8; 32]` |
//! | `compute_pending_blob_hash` | `&PendingBlob` | `[u8; 32]` |
//! | `verify_fallback_event_hash` | `&FallbackEvent, &[u8; 32]` | `bool` |
//!
//! ### Determinism Guarantee
//!
//! Untuk setiap type T yang di-encode:
//! - `encode(x) == encode(x)` untuk input identik (bitwise)
//! - `decode(encode(x)) == x` untuk semua valid x (roundtrip)
//! - `hash(x) == hash(x)` untuk input identik (bitwise)
//!
//! ## Relationship with DA Events
//!
//! ### Encoding Consistency
//!
//! Fallback types menggunakan encoding yang IDENTIK dengan `DAEvent`:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Encoding Consistency                         │
//! └─────────────────────────────────────────────────────────────────┘
//!
//!   DAEvent                          FallbackEvent
//!      │                                  │
//!      ▼                                  ▼
//! encode_event()                  encode_fallback_event()
//!      │                                  │
//!      │    ┌──────────────────────┐      │
//!      └───▶│  Same bincode config │◀─────┘
//!           │  Same byte order     │
//!           │  Same field encoding │
//!           └──────────────────────┘
//! ```
//!
//! ### Hashing Consistency
//!
//! Hash computation menggunakan algoritma yang IDENTIK:
//!
//! | Type | Hash Function | Algorithm |
//! |------|---------------|-----------|
//! | `DAEvent` | `compute_event_hash` | SHA3-256 |
//! | `FallbackEvent` | `compute_fallback_event_hash` | SHA3-256 |
//! | `PendingBlob` | `compute_pending_blob_hash` | SHA3-256 |
//!
//! ### Transport Agnostic
//!
//! Proto layer bersifat transport-agnostic:
//! - Tidak bergantung pada Celestia client implementation
//! - Tidak bergantung pada network protocol
//! - Dapat digunakan dengan DA layer apapun yang menerima bytes
//!
//! Fallback events dapat direkam dan diverifikasi melalui:
//! - Celestia (primary DA)
//! - Validator Quorum DA (fallback)
//! - Emergency DA (tertiary)
//!
//! ## Event Types Summary
//!
//! ### DA Events (Normal Operations)
//!
//! | Event | Deskripsi |
//! |-------|-----------|
//! | `NodeRegistered` | Node baru bergabung ke network |
//! | `ChunkDeclared` | Chunk baru dideklarasikan |
//! | `ReplicaAdded` | Replica ditambahkan ke node |
//! | `ReplicaRemoved` | Replica dihapus dari node |
//! | `DeleteRequested` | Request penghapusan chunk |
//!
//! ### Fallback Events (DA Resilience)
//!
//! | Event | Deskripsi |
//! |-------|-----------|
//! | `FallbackActivated` | DA fallback layer diaktifkan |
//! | `FallbackDeactivated` | DA fallback layer dinonaktifkan |
//! | `ReconciliationStarted` | Proses reconciliation dimulai |
//! | `ReconciliationCompleted` | Proses reconciliation selesai |
//!
//! ### Supporting Types
//!
//! | Type | Deskripsi |
//! |------|-----------|
//! | `PendingBlob` | Blob menunggu reconciliation |
//! | `ReconcileReport` | Laporan hasil reconciliation |
//! | `ReconcileDetail` | Detail per-blob reconciliation |
//! | `ConsistencyReport` | Laporan verifikasi konsistensi |
//! | `ConsistencyMismatch` | Detail ketidakkonsistenan |
//!
//! ## Version Compatibility
//!
//! ### Current Version
//!
//! Proto version: 0.1
//!
//! ### Backward Compatibility Rules
//!
//! Yang TIDAK BOLEH berubah:
//! - Nama dan urutan field dalam struct
//! - Encoding format (bincode little-endian)
//! - Hash algorithm (SHA3-256)
//! - Batch encoding format
//!
//! Yang BOLEH ditambahkan:
//! - Variant baru di enum (di akhir)
//! - Field baru di struct (dengan default value)
//!
//! ### Forward Compatibility
//!
//! Decoder versi lama akan gagal decode event dari versi baru
//! jika ada variant atau field yang tidak dikenal.
//! Gunakan version field untuk deteksi.

// ════════════════════════════════════════════════════════════════════════════════
// MODULE DECLARATIONS
// ════════════════════════════════════════════════════════════════════════════════

/// DA event definitions for normal storage operations.
pub mod da_event;

/// DA health status and error types for monitoring.
pub mod da_health;

/// Deterministic encoding, decoding, and hashing functions.
pub mod encoding;

/// Fallback event types for DA resilience (14A.1A).
pub mod fallback_event;

/// Pending blob structure for reconciliation (14A.1A.6).
pub mod pending_blob;

/// Reconciliation report types (14A.1A.5).
pub mod reconcile_report;

/// Consistency report types for verification (14A.1A.7).
pub mod consistency_report;

/// TSS protocol message types (14A.2B.1.21).
pub mod tss;

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC EXPORTS - DA Core Types
// ════════════════════════════════════════════════════════════════════════════════

pub use da_health::{DAHealthStatus, DAError};
pub use encoding::*;

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC EXPORTS - Fallback Event Types (14A.1A.1 - 14A.1A.4)
// ════════════════════════════════════════════════════════════════════════════════

pub use fallback_event::{
    FallbackEvent,
    FallbackActivated,
    FallbackDeactivated,
    FallbackType,
    ReconciliationStarted,
    ReconciliationCompleted,
    FALLBACK_EVENT_SCHEMA_VERSION,
};

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC EXPORTS - Reconciliation Types (14A.1A.5)
// ════════════════════════════════════════════════════════════════════════════════

pub use reconcile_report::{
    ReconcileReport,
    ReconcileDetail,
    ReconcileStatus,
};

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC EXPORTS - Pending Blob Types (14A.1A.6)
// ════════════════════════════════════════════════════════════════════════════════

pub use pending_blob::{
    PendingBlob,
    MAX_RETRY_COUNT,
};

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC EXPORTS - Consistency Report Types (14A.1A.7)
// ════════════════════════════════════════════════════════════════════════════════

pub use consistency_report::{
    ConsistencyReport,
    ConsistencyMismatch,
    MismatchType,
};

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC EXPORTS - TSS Types (14A.2B.1.21)
// ════════════════════════════════════════════════════════════════════════════════

pub use tss::{BytesWrapper, SignatureBytes, BYTES_WRAPPER_SIZE, SIGNATURE_BYTES_SIZE};

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC EXPORTS - TSS DKG Types (14A.2B.1.22 - 14A.2B.1.24)
// ════════════════════════════════════════════════════════════════════════════════

pub use tss::{
    // DKG proto messages
    DKGRound1PackageProto,
    DKGRound2PackageProto,
    DKGResultProto,
    // DKG error types
    ValidationError as DKGValidationError,
    DecodeError as DKGDecodeError,
    // DKG encoding functions
    encode_dkg_round1,
    decode_dkg_round1,
    compute_dkg_round1_hash,
    encode_dkg_round2,
    decode_dkg_round2,
    encode_dkg_result,
    decode_dkg_result,
    // DKG size constants
    SESSION_ID_SIZE,
    PARTICIPANT_ID_SIZE,
    COMMITMENT_SIZE,
    PROOF_SIZE,
    GROUP_PUBKEY_SIZE,
};

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC EXPORTS - TSS Signing Types (14A.2B.1.25 - 14A.2B.1.27)
// ════════════════════════════════════════════════════════════════════════════════

pub use tss::{
    // Signing proto messages
    SigningRequestProto,
    SigningCommitmentProto,
    PartialSignatureProto,
    AggregateSignatureProto,
    // Signing error types
    SigningValidationError,
    SigningDecodeError,
    // Signing encoding functions
    encode_signing_request,
    decode_signing_request,
    encode_signing_commitment,
    decode_signing_commitment,
    encode_partial_signature,
    decode_partial_signature,
    encode_aggregate_signature,
    decode_aggregate_signature,
    compute_aggregate_signature_hash,
    // Signing size constants
    SIGNER_ID_SIZE,
    MESSAGE_HASH_SIZE,
    HIDING_SIZE,
    BINDING_SIZE,
    SIGNATURE_SHARE_SIZE,
    FROST_SIGNATURE_SIZE,
};

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC EXPORTS - TSS Committee Types (14A.2B.1.28)
// ════════════════════════════════════════════════════════════════════════════════

pub use tss::{
    // Committee proto messages
    CoordinatorMemberProto,
    CoordinatorCommitteeProto,
    // Committee error types
    CommitteeValidationError,
    CommitteeDecodeError,
    // Committee encoding functions
    encode_committee,
    decode_committee,
    compute_committee_hash,
    // Committee size constants
    COORDINATOR_ID_SIZE,
    VALIDATOR_ID_SIZE,
    PUBKEY_SIZE,
};

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC EXPORTS - TSS Receipt Types (14A.2B.1.29)
// ════════════════════════════════════════════════════════════════════════════════

pub use tss::{
    // Receipt proto messages
    ReceiptDataProto,
    ThresholdReceiptProto,
    // Receipt encoding functions
    encode_receipt,
    decode_receipt,
    compute_receipt_hash,
    // Receipt size constants
    WORKLOAD_ID_SIZE,
    BLOB_HASH_SIZE,
    NODE_ID_SIZE,
    COMMITTEE_HASH_SIZE,
};

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Proto crate version string.
///
/// Digunakan untuk:
/// - Version tracking dalam logs dan metrics
/// - Compatibility checking saat decode
/// - Audit trail
pub const PROTO_VERSION: &str = "0.1";