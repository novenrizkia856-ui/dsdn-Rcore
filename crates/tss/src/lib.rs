//! # DSDN TSS Crate
//!
//! Implementasi lengkap Threshold Signature Scheme (TSS) berbasis FROST
//! untuk sistem DSDN (Distributed Storage and Data Network).
//!
//! ## Overview
//!
//! Crate ini menyediakan:
//! - **Distributed Key Generation (DKG)**: Protocol untuk generate shared key
//! - **Threshold Signing**: t-of-n signing tanpa single point of failure  
//! - **Verification**: Fungsi verifikasi untuk aggregate dan partial signatures
//! - **KeyShare Management**: Serialization dan encryption untuk key storage
//!
//! ## Arsitektur
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                         DSDN TSS Architecture                                │
//! └─────────────────────────────────────────────────────────────────────────────┘
//!
//!   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
//!   │   Types     │     │ Primitives  │     │    DKG      │     │  Signing    │
//!   │             │     │             │     │             │     │             │
//!   │ SessionId   │     │ GroupPubKey │     │ DKGSession  │     │SignSession  │
//!   │ ParticipantId│    │ SecretShare │     │ DKGState    │     │SigningState │
//!   │ SignerId    │     │ FrostSig    │     │ KeyShare    │     │PartialSig   │
//!   └──────┬──────┘     └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
//!          │                   │                   │                   │
//!          └───────────────────┴───────────────────┴───────────────────┘
//!                                      │
//!                    ┌─────────────────┴─────────────────┐
//!                    │                                   │
//!              ┌─────▼─────┐                       ┌─────▼─────┐
//!              │  Verify   │                       │ KeyShare  │
//!              │           │                       │ Serialize │
//!              │verify_agg │                       │           │
//!              │verify_part│                       │ encrypted │
//!              └───────────┘                       │ plaintext │
//!                                                  └───────────┘
//! ```
//!
//! ## Protocol Flow
//!
//! ### Phase 1: Distributed Key Generation (DKG)
//!
//! DKG menggunakan real FROST DKG protocol (Pedersen DKG / Feldman VSS variant)
//! dari `frost-ed25519` (ZCash Foundation). Protocol terdiri dari dua round:
//!
//! **Round 1** (`frost::keys::dkg::part1`): Setiap participant generate random
//! polynomial, compute Feldman VSS commitments (t curve points), dan Schnorr
//! proof of knowledge. Output di-broadcast ke semua participants.
//!
//! **Round 2** (`frost::keys::dkg::part2` + `part3`): Setiap participant
//! memverifikasi semua commitments dan proofs dari Round 1, kemudian mengevaluasi
//! polynomialnya di titik masing-masing peer. Shares dikirim secara private.
//! Setelah menerima shares, setiap participant memverifikasi terhadap VSS
//! commitments dan menghitung final signing share + group public key.
//!
//! **Key Finalization** (`process_round2` → `frost::keys::dkg::part3`): Output
//! berupa `KeyShare` yang membungkus real frost `KeyPackage` components:
//! - `signing_share()`: Ed25519 signing scalar (32 bytes, unique per participant)
//! - `group_public_key()`: Ed25519 verifying key (32 bytes, identical across all)
//! - `participant_pubkey()`: Verifying share individual (32 bytes, unique)
//!
//! `KeyShare` dapat di-serialize via `KeyShareSerialization` trait (encrypted
//! untuk production, plaintext untuk testing). Serialization bersifat deterministik
//! dan aman — secret share dienkripsi dengan ChaCha20-Poly1305 style construction.
//!
//! Output DKG kompatibel dengan `frost-ed25519` threshold signing.
//!
//! ```text
//! Participant A          Participant B          Participant C
//!      │                      │                      │
//!      │ ──── Round 1 Package ───────────────────────>
//!      │ <─── Round 1 Package ────────────────────────
//!      │                      │ ──── Round 1 ──────> │
//!      │                      │ <─── Round 1 ─────── │
//!      │                      │                      │
//!      │ ──── Round 2 Package ───────────────────────>
//!      │ <─── Round 2 Package ────────────────────────
//!      │                      │                      │
//!      ▼                      ▼                      ▼
//!   KeyShare              KeyShare              KeyShare
//!   (share_a)             (share_b)             (share_c)
//!      │                      │                      │
//!      └──────────────────────┼──────────────────────┘
//!                             │
//!                      GroupPublicKey
//!                    (sama untuk semua)
//! ```
//!
//! ### Phase 2: Threshold Signing
//!
//! Signing menggunakan real FROST 2-round signing protocol dari `frost-ed25519`.
//! Setiap signing session melibatkan minimal `t` signers dari `n` total participants.
//!
//! **Round 1 — Commitment** (`frost::round1::commit`): Setiap signer yang berpartisipasi
//! generate random hiding dan binding nonces via `frost::round1::commit(signing_share, rng)`.
//! Nonces disimpan secara internal di `LocalThresholdSigner`. Commitment (nonce commitments
//! berupa compressed Edwards Y points) di-broadcast ke coordinator.
//! **Nonces TIDAK boleh di-reuse** — setiap signing session membutuhkan nonces baru.
//!
//! **Round 2 — Partial Signature** (`frost::round2::sign`): Setelah menerima semua
//! commitments, coordinator mendistribusikan signing package (message + all commitments).
//! Setiap signer memanggil `frost::round2::sign(signing_package, nonces, key_package)`
//! untuk menghasilkan real FROST `SignatureShare` (partial signature). Nonces di-zeroize
//! setelah digunakan untuk mencegah nonce reuse.
//!
//! **Aggregation** (`frost::aggregate`): Coordinator mengumpulkan minimal `t` partial
//! signatures dan memanggil `frost::aggregate()` untuk menghasilkan valid Ed25519
//! aggregate signature yang dapat diverifikasi menggunakan group public key.
//! `aggregate_signatures()` membangun semua frost types yang diperlukan — `SigningPackage`,
//! `BTreeMap<Identifier, SignatureShare>`, dan `PublicKeyPackage` — kemudian mendelegasikan
//! ke `frost::aggregate()`. Hasil berupa 64-byte Ed25519 signature (R ‖ s).
//!
//! **Nonce Safety**: `frost::round1::SigningNonces` implements `Zeroize` — nonces
//! secara otomatis di-clear saat di-drop. `LocalThresholdSigner` menjamin nonces
//! hanya digunakan sekali: commitment hanya dapat di-generate jika tidak ada
//! pending nonces, dan sign mengkonsumsi nonces (set ke None).
//!
//! **Kompatibilitas**: Semua partial signatures yang dihasilkan kompatibel dengan
//! `frost-ed25519::aggregate()` dan menghasilkan standard Ed25519 signatures.
//!
//! ```text
//! Signer 1                Signer 2               Coordinator
//!      │                      │                      │
//!      │ frost::round1::commit()                     │
//!      │ ──── Commitment ────────────────────────────>
//!      │                      │ frost::round1::commit()
//!      │                      │ ──── Commitment ────>│
//!      │                      │                      │
//!      │ <── All Commitments ────────────────────────│
//!      │                      │ <── All Commitments ─│
//!      │                      │                      │
//!      │ frost::round2::sign()                       │
//!      │ ── Partial Signature ──────────────────────>│
//!      │                      │ frost::round2::sign()│
//!      │                      │ ── Partial Sig ─────>│
//!      │                      │                      │
//!      │                      │         frost::aggregate()
//!      │                      │                      │
//!      │                      │         AggregateSignature
//!      │                      │         (valid Ed25519 sig)
//! ```
//!
//! ## Modules
//!
//! | Module | Deskripsi |
//! |--------|-----------|
//! | [`types`] | Identifier types (SessionId, ParticipantId, SignerId) |
//! | [`error`] | Error types (DKGError, SigningError, TSSError) |
//! | [`primitives`] | Cryptographic primitives (keys, signatures, commitments) |
//! | [`dkg`] | DKG protocol state machine dan participants |
//! | [`signing`] | Signing protocol state machine dan aggregation |
//! | [`verify`] | Signature verification functions |
//! | [`keyshare`] | KeyShare serialization dan encryption |
//! | [`frost_adapter`] | Adapter layer: internal types ↔ frost-ed25519 types |
//!
//! ## Contoh Penggunaan
//!
//! ### Basic Identifier Usage
//!
//! ```rust
//! use dsdn_tss::{SessionId, ParticipantId, SignerId};
//!
//! // Generate random identifiers
//! let session = SessionId::new();
//! let participant = ParticipantId::new();
//! let signer = SignerId::new();
//!
//! // Hex representation untuk logging
//! println!("Session: {}", session.to_hex());
//!
//! // Deterministic construction
//! let known_bytes = [0x42u8; 32];
//! let session = SessionId::from_bytes(known_bytes);
//! ```
//!
//! ### DKG Session Setup
//!
//! ```rust
//! use dsdn_tss::{DKGSession, SessionId, ParticipantId};
//!
//! let session_id = SessionId::new();
//! let participants = vec![
//!     ParticipantId::new(),
//!     ParticipantId::new(),
//!     ParticipantId::new(),
//! ];
//!
//! // Create 2-of-3 DKG session
//! let session = DKGSession::new(session_id, participants, 2);
//! assert!(session.is_ok());
//! ```
//!
//! ### Signing Session Setup
//!
//! ```rust
//! use dsdn_tss::{SigningSession, SessionId, SignerId};
//!
//! let session_id = SessionId::new();
//! let signers = vec![
//!     SignerId::new(),
//!     SignerId::new(),
//!     SignerId::new(),
//! ];
//! let message = b"message to sign".to_vec();
//!
//! // Create signing session with threshold 2
//! let session = SigningSession::new(session_id, message, signers, 2);
//! assert!(session.is_ok());
//! ```
//!
//! ### Verification
//!
//! ```rust,ignore
//! use dsdn_tss::verify::{verify_aggregate, verify_partial, verify_frost_signature_bytes};
//!
//! // Verify aggregate signature (real frost_ed25519::VerifyingKey::verify)
//! let is_valid = verify_aggregate(&aggregate_sig, b"message", &group_pubkey);
//!
//! // Verify partial signature (structural + frost type validation)
//! let is_valid = verify_partial(&partial_sig, b"message", &participant_pk, &all_commitments);
//!
//! // Verify from raw bytes (chain integration)
//! let is_valid = verify_frost_signature_bytes(&pubkey_bytes, b"message", &sig_bytes);
//! ```
//!
//! ### KeyShare Serialization
//!
//! ```rust,ignore
//! use dsdn_tss::keyshare::KeyShareSerialization;
//!
//! // Encrypted serialization (production)
//! let encrypted = key_share.serialize_encrypted(&encryption_key)?;
//! let recovered = KeyShare::deserialize_encrypted(&encrypted, &encryption_key)?;
//!
//! // Plaintext serialization (testing only!)
//! let plaintext = key_share.serialize_plaintext();
//! let recovered = KeyShare::deserialize_plaintext(&plaintext)?;
//! ```
//!
//! ## Security Considerations
//!
//! ### Secret Data Handling
//!
//! - `SecretShare` dan `EncryptionKey` implement `ZeroizeOnDrop`
//! - Tidak ada `Debug` implementation untuk secret types
//! - Tidak ada `Serialize`/`Deserialize` untuk raw secret types
//!
//! ### Thread Safety
//!
//! Semua public types adalah `Send + Sync`:
//! - Identifier types: immutable setelah construction
//! - Error types: contain only cloneable data
//! - Primitive types: immutable byte arrays
//! - Session types: designed for single-threaded state machine
//!
//! ### Cryptographic Notes
//!
//! - Menggunakan SHA3-256 untuk hashing internal
//! - Domain separation untuk semua hash operations
//! - Real FROST cryptography via `frost-ed25519` (ZCash Foundation)
//! - DKG menggunakan real Feldman VSS (Pedersen DKG) dari `frost::keys::dkg`
//! - Signing menggunakan real FROST 2-round protocol:
//!   - Round 1: `frost::round1::commit()` generates real hiding + binding nonces
//!   - Round 2: `frost::round2::sign()` computes real partial signatures
//!   - Aggregation: `frost::aggregate()` produces standard Ed25519 signatures (64 bytes)
//! - Nonces di-zeroize setelah sign via `Zeroize` trait pada `frost::round1::SigningNonces`
//! - Aggregate signature = 64-byte Ed25519 signature (R ‖ s), verifiable via group public key
//! - Verification: `frost_ed25519::VerifyingKey::verify()` — standard Ed25519 verification
//! - `verify_frost_signature_bytes()` provides raw-bytes verification for chain integration
//! - `frost_adapter` module menyediakan konversi ke/dari real Ed25519 FROST types
//! - DKG output (KeyShare) kompatibel dengan `frost-ed25519` threshold signing
//!
//! ### Committee Formation & BFT Threshold
//!
//! Committee threshold menggunakan Byzantine fault tolerance formula:
//!
//! ```text
//! t = ceil(2n/3) + 1
//! ```
//!
//! Dimana `n` adalah jumlah total committee members dan `t` adalah jumlah minimum
//! signatures yang diperlukan. Formula ini menjamin:
//! - Selalu > 2/3 dari committee (safety terhadap Byzantine failures)
//! - Selalu >= 2 (minimum untuk threshold signatures)
//! - Selalu <= n (clamped)
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │ Committee Size (n) │ Threshold (t) │ Max Offline     │
//! ├────────────────────┼───────────────┼─────────────────┤
//! │         3          │       3       │       0         │
//! │         4          │       4       │       0         │
//! │         5          │       5       │       0         │
//! │         6          │       5       │       1         │
//! │         7          │       6       │       1         │
//! │        10          │       8       │       2         │
//! │        15          │      11       │       4         │
//! │        20          │      15       │       5         │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! ### Failure Handling & Recovery
//!
//! **DKG Failures:**
//! - `InvalidThreshold`: threshold < 2, threshold > total, atau total < 2
//! - `DuplicateParticipant`: ParticipantId sama terdeteksi
//! - `InvalidPackage`: Round 1/2 package gagal verifikasi (corrupt/tampered)
//! - `MissingPackages`: Tidak semua packages diterima
//! - Recovery: Restart DKG session dari awal dengan SessionId baru
//!
//! **Signing Failures:**
//! - `BelowThreshold`: Kurang dari `t` signers berpartisipasi
//! - `InvalidPartialSignature`: Partial signature gagal verifikasi
//! - `NonceReuse`: Nonces sudah digunakan (fatal — abort session)
//! - `AggregationError`: `frost::aggregate()` gagal
//! - Recovery: Retry signing session dengan nonces baru (JANGAN reuse nonces)
//!
//! **Verification Failures:**
//! - `InvalidSignature`: Signature bytes bukan valid Ed25519 signature
//! - `InvalidPublicKey`: Public key bukan valid Ed25519 point
//! - `MessageMismatch`: Signature tidak cocok dengan message
//! - Semua verification functions mengembalikan `bool` (tidak panic)
//!
//! **KeyShare Serialization Failures:**
//! - `DecryptionError`: Wrong encryption key atau corrupted ciphertext
//! - `InvalidFormat`: Data tidak mengikuti expected layout
//! - Recovery: Re-derive key dari DKG backup atau re-run DKG
//!
//! ### Known Identifier Derivation Behavior
//!
//! DKG menggunakan `frost::Identifier::derive()` (hash-to-field) untuk mengkonversi
//! `ParticipantId` → `frost::Identifier`, sementara signing path di
//! `LocalThresholdSigner` menggunakan `Identifier::deserialize()` (raw bytes).
//! Kedua metode ini menghasilkan identifier yang **berbeda** untuk input yang sama.
//!
//! Untuk end-to-end correctness (DKG → Sign → Verify), pastikan:
//! 1. Gunakan `participant_id_to_frost_identifier()` untuk derive identifier DKG
//! 2. Build `KeyPackage` secara manual dengan derived identifier yang benar
//! 3. Atau gunakan `generate_with_dealer()` untuk testing yang konsisten
//!
//! ## Feature Flags
//!
//! Crate ini tidak memiliki feature flags saat ini.
//! Semua functionality tersedia secara default.
//!
//! ## Compatibility
//!
//! - Minimum Rust version: 1.70
//! - No unsafe code
//! - No std dependencies (tapi belum no_std compatible)

// ════════════════════════════════════════════════════════════════════════════════
// MODULE DECLARATIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Basic identifier types untuk TSS operations.
///
/// Module ini menyediakan tiga identifier types:
/// - `SessionId`: Untuk DKG dan signing sessions
/// - `ParticipantId`: Untuk DKG participants
/// - `SignerId`: Untuk threshold signers
pub mod types;

/// Error types untuk DKG dan signing operations.
///
/// Module ini menyediakan:
/// - `DKGError`: Errors dalam DKG protocol
/// - `SigningError`: Errors dalam signing protocol
/// - `TSSError`: Wrapper untuk semua TSS errors
pub mod error;

/// Cryptographic primitive types untuk FROST TSS.
///
/// Module ini menyediakan:
/// - `GroupPublicKey`: Shared public key hasil DKG
/// - `ParticipantPublicKey`: Individual participant's public key
/// - `SecretShare`: Secret share (sensitive data)
/// - `FrostSignature`: Aggregate signature (R || s)
/// - `FrostSignatureShare`: Partial signature share
/// - `SigningCommitment`: Commitment untuk signing round
/// - `EncryptionKey`: Key untuk share encryption
pub mod primitives;

/// DKG (Distributed Key Generation) types dan state machine.
///
/// Module ini menyediakan:
/// - `DKGState`: State machine untuk DKG lifecycle
/// - `DKGSession`: Session controller
/// - `DKGParticipant` trait dan `LocalDKGParticipant` implementation
/// - `Round1Package` dan `Round2Package` untuk protocol messages
/// - `KeyShare`: Hasil akhir DKG
pub mod dkg;

/// Signing types dan state machine untuk FROST threshold signing.
///
/// Module ini menyediakan:
/// - `SigningState`: State machine untuk signing lifecycle
/// - `SigningSession`: Session controller
/// - `PartialSignature`: Partial signature dari signer
/// - `AggregateSignature`: Final aggregate signature
/// - `ThresholdSigner` trait dan `LocalThresholdSigner` implementation
/// - `aggregate_signatures`: Aggregation function
pub mod signing;

/// Signature verification functions.
///
/// Module ini menyediakan:
/// - `verify_aggregate`: Verify final aggregate signature via `frost::VerifyingKey::verify()`
/// - `verify_aggregate_with_hash`: Verify with pre-computed hash (no re-hash)
/// - `verify_partial`: Structural verification of individual partial signature
/// - `verify_partials_batch`: Batch structural verification
/// - `verify_frost_signature_bytes`: Raw bytes verification for chain integration
pub mod verify;

/// KeyShare serialization dan encryption.
///
/// Module ini menyediakan:
/// - `KeyShareSerialization` trait untuk serialize/deserialize KeyShare
/// - Encrypted serialization untuk production
/// - Plaintext serialization untuk testing
pub mod keyshare;

/// FROST Crypto Adapter Module.
///
/// Adapter layer antara tipe internal crate ini dan library resmi
/// `frost-ed25519` (ZCash Foundation). Menyediakan konversi dua arah
/// untuk semua tipe kriptografis:
///
/// - [`GroupPublicKey`] ↔ `frost_ed25519::VerifyingKey`
/// - [`SecretShare`] ↔ `frost_ed25519::keys::SigningShare`
/// - [`FrostSignature`] ↔ `frost_ed25519::Signature`
/// - [`SigningCommitment`] ↔ `frost_ed25519::round1::SigningCommitments`
/// - [`FrostSignatureShare`] ↔ `frost_ed25519::round2::SignatureShare`
/// - [`KeyShare`] ↔ `frost_ed25519::keys::KeyPackage`
///
/// Serta mapping `frost_ed25519::Error` → [`TSSError`].
///
/// Semua konversi deterministic, byte-identical, dan return `Result`.
pub mod frost_adapter;

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC API EXPORTS
// ════════════════════════════════════════════════════════════════════════════════

// Identifier types (14A.2B.1.1)
pub use types::{ParticipantId, SessionId, SignerId, IDENTIFIER_SIZE};

// Error types (14A.2B.1.2)
pub use error::{DKGError, SigningError, TSSError};

// Cryptographic primitives (14A.2B.1.3)
pub use primitives::{
    EncryptionKey, FrostSignature, FrostSignatureShare, GroupPublicKey, ParticipantPublicKey,
    SecretShare, SigningCommitment, PUBLIC_KEY_SIZE, SCALAR_SIZE, SIGNATURE_SIZE,
};

// DKG types (14A.2B.1.4, 14A.2B.1.5 & 14A.2B.1.6)
pub use dkg::{
    DKGParticipant, DKGSession, DKGSessionConfig, DKGState, KeyShare, LocalDKGParticipant,
    LocalParticipantState, Round1Package, Round2Package,
};

// Signing types (14A.2B.1.7, 14A.2B.1.8 & 14A.2B.1.9)
pub use signing::{
    aggregate_signatures, AggregateSignature, LocalThresholdSigner, PartialSignature,
    SigningSession, SigningState, ThresholdSigner,
};

// Verification functions (14A.2B.1.10)
pub use verify::{
    verify_aggregate, verify_aggregate_with_hash, verify_frost_signature_bytes,
    verify_partial, verify_partial_with_hash, verify_partials_batch,
};

// KeyShare serialization (14A.2B.1.10)
pub use keyshare::KeyShareSerialization;

// ════════════════════════════════════════════════════════════════════════════════
// CRATE-LEVEL CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Version string untuk crate ini.
pub const TSS_VERSION: &str = "0.1.0";

/// Minimum supported threshold (t).
pub const MIN_THRESHOLD: u8 = 2;

/// Maximum supported participants (n).
pub const MAX_PARTICIPANTS: u8 = 255;

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────────────────────
    // IDENTIFIER EXPORTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_re_exports_available() {
        let _session = SessionId::new();
        let _participant = ParticipantId::new();
        let _signer = SignerId::new();
    }

    #[test]
    fn test_identifier_size_constant() {
        assert_eq!(IDENTIFIER_SIZE, 32);
    }

    #[test]
    fn test_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        
        assert_send_sync::<SessionId>();
        assert_send_sync::<ParticipantId>();
        assert_send_sync::<SignerId>();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // ERROR EXPORTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_error_re_exports_available() {
        let _dkg_err = DKGError::InvalidThreshold {
            threshold: 5,
            total: 3,
        };
        let _signing_err = SigningError::MessageMismatch;
        let _tss_err = TSSError::Crypto("test".to_string());
    }

    #[test]
    fn test_error_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        
        assert_send_sync::<DKGError>();
        assert_send_sync::<SigningError>();
        assert_send_sync::<TSSError>();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // PRIMITIVES EXPORTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_primitives_re_exports_available() {
        let _gpk = GroupPublicKey::from_bytes([0x02; 32]);
        let _ppk = ParticipantPublicKey::from_bytes([0x02; 32]);
        let _ss = SecretShare::from_bytes([0x42; 32]);
        let _sig = FrostSignature::from_bytes([0x02; 64]);
        let _share = FrostSignatureShare::from_bytes([0x42; 32]);
        let _commit = SigningCommitment::from_parts([0xAA; 32], [0xBB; 32]);
        let _ek = EncryptionKey::from_bytes([0x42; 32]);
    }

    #[test]
    fn test_primitives_constants_available() {
        assert_eq!(PUBLIC_KEY_SIZE, 32);
        assert_eq!(SCALAR_SIZE, 32);
        assert_eq!(SIGNATURE_SIZE, 64);
    }

    #[test]
    fn test_primitives_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        
        assert_send_sync::<GroupPublicKey>();
        assert_send_sync::<ParticipantPublicKey>();
        assert_send_sync::<SecretShare>();
        assert_send_sync::<FrostSignature>();
        assert_send_sync::<FrostSignatureShare>();
        assert_send_sync::<SigningCommitment>();
        assert_send_sync::<EncryptionKey>();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DKG EXPORTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_dkg_re_exports_available() {
        let _state = DKGState::Initialized;
        // Round1Package and Round2Package now wrap frost types;
        // they are constructed internally by LocalDKGParticipant.
        // Verify they are accessible as types.
        fn _accepts_r1(_p: &Round1Package) {}
        fn _accepts_r2(_p: &Round2Package) {}
    }

    #[test]
    fn test_dkg_session_re_export_available() {
        let session_id = SessionId::new();
        let participants = vec![
            ParticipantId::new(),
            ParticipantId::new(),
            ParticipantId::new(),
        ];
        let session = DKGSession::new(session_id, participants, 2);
        assert!(session.is_ok());
    }

    #[test]
    fn test_dkg_session_config_re_export_available() {
        let config = DKGSessionConfig::default();
        assert_eq!(config.timeout_secs(), 300);
    }

    #[test]
    fn test_dkg_participant_re_exports_available() {
        let session_id = SessionId::new();
        let participant_id = ParticipantId::new();
        let participant = LocalDKGParticipant::new(
            participant_id,
            session_id,
            2,
            3,
        );
        assert!(participant.is_ok());
    }

    #[test]
    fn test_dkg_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        
        assert_send_sync::<DKGState>();
        assert_send_sync::<Round1Package>();
        assert_send_sync::<Round2Package>();
        assert_send_sync::<DKGSession>();
        assert_send_sync::<DKGSessionConfig>();
        assert_send_sync::<LocalDKGParticipant>();
        assert_send_sync::<LocalParticipantState>();
        assert_send_sync::<KeyShare>();
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SIGNING EXPORTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_signing_session_re_export_available() {
        let session_id = SessionId::new();
        let signers = vec![
            SignerId::new(),
            SignerId::new(),
            SignerId::new(),
        ];
        let message = b"test message".to_vec();
        let session = SigningSession::new(session_id, message, signers, 2);
        assert!(session.is_ok());
    }

    #[test]
    fn test_signing_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        
        assert_send_sync::<SigningState>();
        assert_send_sync::<SigningSession>();
        assert_send_sync::<PartialSignature>();
        assert_send_sync::<AggregateSignature>();
    }

    #[test]
    fn test_aggregate_signatures_re_export() {
        // Just verify the function is accessible with new real-FROST signature
        let _fn_ptr: fn(
            &[u8],
            &[PartialSignature],
            &GroupPublicKey,
            &[(SignerId, ParticipantPublicKey)],
            &[u8; 32],
        ) -> Result<AggregateSignature, SigningError> = aggregate_signatures;
    }

    #[test]
    fn test_threshold_signer_trait_re_export() {
        // Verify trait is accessible
        fn _takes_signer<T: ThresholdSigner>(_signer: &T) {}
    }

    // ────────────────────────────────────────────────────────────────────────────
    // VERIFICATION EXPORTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_functions_re_export() {
        // Verify functions are accessible
        let _fn1: fn(&AggregateSignature, &[u8], &GroupPublicKey) -> bool = verify_aggregate;
        let _fn2: fn(&AggregateSignature, &[u8], &[u8; 32], &GroupPublicKey) -> bool = verify_aggregate_with_hash;
        let _fn3: fn(&PartialSignature, &[u8], &ParticipantPublicKey, &[(SignerId, SigningCommitment)]) -> bool = verify_partial;
        let _fn4: fn(&[u8; 32], &[u8], &[u8]) -> bool = verify_frost_signature_bytes;
    }

    // ────────────────────────────────────────────────────────────────────────────
    // KEYSHARE SERIALIZATION EXPORTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_keyshare_serialization_trait_re_export() {
        // Verify trait is accessible
        fn _uses_serialization<T: KeyShareSerialization>(_ks: &T) {}
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CRATE CONSTANTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_version_string() {
        assert!(!TSS_VERSION.is_empty());
        assert_eq!(TSS_VERSION, "0.1.0");
    }

    #[test]
    fn test_threshold_constants() {
        assert_eq!(MIN_THRESHOLD, 2);
        assert_eq!(MAX_PARTICIPANTS, 255);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // INTEGRATION SANITY CHECK
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_full_type_chain_compiles() {
        // This test verifies that all the types work together
        
        // DKG types
        let session_id = SessionId::new();
        let participant_id = ParticipantId::new();
        
        // Primitives
        let _gpk = GroupPublicKey::from_bytes([0x01; 32]).unwrap();
        let _sig = FrostSignature::from_bytes([0x01; 64]).unwrap();
        
        // Signing types  
        let signer_id = SignerId::from_bytes(*participant_id.as_bytes());
        let commitment = SigningCommitment::from_parts([0x01; 32], [0x02; 32]).unwrap();
        let share = FrostSignatureShare::from_bytes([0x01; 32]).unwrap();
        let _partial = PartialSignature::new(signer_id, share, commitment);
        
        // Session types
        let participants = vec![ParticipantId::new(), ParticipantId::new()];
        let _dkg_session = DKGSession::new(session_id.clone(), participants, 2).unwrap();
        
        let signers = vec![SignerId::new(), SignerId::new()];
        let _signing_session = SigningSession::new(session_id, b"msg".to_vec(), signers, 2).unwrap();
    }
}