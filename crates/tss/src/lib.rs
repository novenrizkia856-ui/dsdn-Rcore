//! # DSDN TSS Crate
//!
//! Crate ini menyediakan foundational types dan cryptographic primitives untuk
//! Threshold Signature Scheme (TSS) dalam sistem DSDN.
//!
//! ## Peran Crate
//!
//! `dsdn-tss` adalah foundation crate yang menyediakan:
//! - Identifier types untuk DKG dan signing sessions
//! - Cryptographic primitive types (akan ditambahkan di tahap selanjutnya)
//! - Error types untuk operasi TSS
//!
//! Crate ini TIDAK mengimplementasikan protocol DKG atau signing.
//! Protocol implementation berada di layer yang lebih tinggi.
//!
//! ## Arsitektur TSS di DSDN
//!
//! TSS digunakan untuk multi-coordinator system dimana:
//! - Committee coordinators menjalankan DKG untuk generate shared key
//! - Threshold signing (t-of-n) digunakan untuk sign receipts
//! - Tidak ada single coordinator yang memiliki full signing key
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    TSS Component Hierarchy                       │
//! └─────────────────────────────────────────────────────────────────┘
//!
//!                        ┌─────────────────┐
//!                        │   dsdn-tss      │  ← Foundation (crate ini)
//!                        │   (types)       │
//!                        └────────┬────────┘
//!                                 │
//!              ┌──────────────────┼──────────────────┐
//!              │                  │                  │
//!              ▼                  ▼                  ▼
//!      ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
//!      │  DKG Types   │  │ Signing Types│  │ Verification │
//!      │  (tahap 4-6) │  │ (tahap 7-9)  │  │ (tahap 10)   │
//!      └──────────────┘  └──────────────┘  └──────────────┘
//! ```
//!
//! ## Types dalam Crate Ini
//!
//! ### Identifier Types (tahap 14A.2B.1.1)
//!
//! | Type | Deskripsi | Ukuran |
//! |------|-----------|--------|
//! | `SessionId` | Identifier untuk DKG/signing session | 32 bytes |
//! | `ParticipantId` | Identifier untuk DKG participant | 32 bytes |
//! | `SignerId` | Identifier untuk threshold signer | 32 bytes |
//!
//! Semua identifier types memiliki:
//! - Random generation via `new()`
//! - Deterministic construction via `from_bytes()`
//! - Hex encoding via `to_hex()`
//! - Serialization via serde
//!
//! ## Keamanan
//!
//! - Random identifier generation menggunakan cryptographically secure RNG
//! - Secret data akan menggunakan `zeroize` untuk secure memory cleanup
//! - Tidak ada logging atau display secret values
//!
//! ## Thread Safety
//!
//! Semua types dalam crate ini adalah `Send` dan `Sync` secara struktural
//! karena hanya berisi data immutable setelah construction.
//!
//! ## Contoh Penggunaan
//!
//! ```rust
//! use dsdn_tss::{SessionId, ParticipantId, SignerId};
//!
//! // Buat identifier baru
//! let session_id = SessionId::new();
//! let participant_id = ParticipantId::new();
//! let signer_id = SignerId::new();
//!
//! // Logging dengan hex representation
//! println!("Session: {}", session_id.to_hex());
//!
//! // Construct dari known bytes
//! let known_bytes = [0x42u8; 32];
//! let session = SessionId::from_bytes(known_bytes);
//! assert_eq!(session.as_bytes(), &known_bytes);
//! ```

// ════════════════════════════════════════════════════════════════════════════════
// MODULE DECLARATIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Basic identifier types untuk TSS operations.
pub mod types;

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC API EXPORTS
// ════════════════════════════════════════════════════════════════════════════════

// Identifier types (14A.2B.1.1)
pub use types::{ParticipantId, SessionId, SignerId, IDENTIFIER_SIZE};

// ════════════════════════════════════════════════════════════════════════════════
// CRATE-LEVEL CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Version string untuk crate ini.
pub const TSS_VERSION: &str = "0.1.0";

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_re_exports_available() {
        // Pastikan semua types dapat diakses via crate root
        let _session = SessionId::new();
        let _participant = ParticipantId::new();
        let _signer = SignerId::new();
    }

    #[test]
    fn test_identifier_size_constant() {
        assert_eq!(IDENTIFIER_SIZE, 32);
    }

    #[test]
    fn test_version_string() {
        assert!(!TSS_VERSION.is_empty());
    }

    #[test]
    fn test_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        
        assert_send_sync::<SessionId>();
        assert_send_sync::<ParticipantId>();
        assert_send_sync::<SignerId>();
    }
}