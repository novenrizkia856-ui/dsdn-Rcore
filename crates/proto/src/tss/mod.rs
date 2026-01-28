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
//! **PENTING**: Module ini dalam tahap struktural.
//!
//! Saat ini module menyediakan:
//! - Wrapper types untuk raw bytes (`BytesWrapper`, `SignatureBytes`)
//!
//! Message types yang tercantum di tabel di atas BELUM diimplementasikan
//! dan akan ditambahkan di tahap selanjutnya.
//!
//! ## Submodules
//!
//! | Module | Description |
//! |--------|-------------|
//! | `types` | Basic wrapper types untuk bytes dan signatures |

pub mod types;

// Re-export wrapper types
pub use types::{BytesWrapper, SignatureBytes};

// Re-export size constants
pub use types::{BYTES_WRAPPER_SIZE, SIGNATURE_BYTES_SIZE};