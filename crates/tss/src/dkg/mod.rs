//! # DKG (Distributed Key Generation) Module
//!
//! Module ini menyediakan types untuk Distributed Key Generation protocol
//! dalam FROST Threshold Signature Scheme.
//!
//! ## Peran DKG dalam TSS
//!
//! DKG adalah proses dimana `n` participants secara bersama-sama menghasilkan:
//! - **Group Public Key**: Shared public key yang digunakan untuk verifikasi signatures
//! - **Secret Shares**: Setiap participant menerima share dari secret key
//!
//! Tidak ada satu participant pun yang mengetahui full secret key.
//! Threshold `t` shares diperlukan untuk menghasilkan valid signature.
//!
//! ## Alur Protocol
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                          DKG Protocol Flow                                   │
//! └─────────────────────────────────────────────────────────────────────────────┘
//!
//!   Initialized
//!       │
//!       ▼
//!   Round1Commitment ──────────────────────────────────────────┐
//!       │                                                       │
//!       │ (broadcast Round1Package)                             │
//!       ▼                                                       │
//!   Round1Complete { commitments }                              │
//!       │                                                       │
//!       ▼                                                       │
//!   Round2Share ────────────────────────────────────────────────┤
//!       │                                                       │
//!       │ (send Round2Package to each participant)              │
//!       ▼                                                       │
//!   Round2Complete { shares }                                   │
//!       │                                                       │
//!       ├─────────────────────┐                                 │
//!       ▼                     ▼                                 │
//!   Completed { group_pubkey }    Failed { error } ◄────────────┘
//! ```
//!
//! ### Round 1: Commitment Phase
//!
//! 1. Setiap participant generate polynomial coefficients
//! 2. Participant broadcast `Round1Package` berisi:
//!    - Pedersen commitment ke polynomial
//!    - Schnorr proof of knowledge
//! 3. Semua participants collect dan verify commitments
//!
//! ### Round 2: Share Distribution
//!
//! 1. Setiap participant menghitung share untuk participant lain
//! 2. Shares dienkripsi dengan `EncryptionKey` (derived via ECDH)
//! 3. `Round2Package` dikirim secara private ke masing-masing recipient
//! 4. Recipients verify shares terhadap commitments dari Round 1
//!
//! ### Completion
//!
//! Jika semua shares valid:
//! - State menjadi `Completed` dengan `GroupPublicKey`
//! - Setiap participant memiliki `SecretShare` untuk signing
//!
//! Jika ada kegagalan:
//! - State menjadi `Failed` dengan `DKGError`
//! - Protocol harus di-restart
//!
//! ## Catatan Implementasi
//!
//! Module ini hanya menyediakan **types dan state machine**.
//! Kriptografi detail (polynomial evaluation, Schnorr proofs, etc.)
//! akan diimplementasikan di tahap selanjutnya.
//!
//! Saat ini:
//! - `verify_proof()` adalah stub yang selalu return true
//! - `decrypt()` adalah stub dengan basic XOR simulation
//!
//! ## Contoh Penggunaan
//!
//! ```rust
//! use dsdn_tss::dkg::{DKGState, Round1Package, Round2Package};
//! use dsdn_tss::{ParticipantId, SessionId};
//!
//! // Create initial state
//! let state = DKGState::Initialized;
//! assert!(!state.is_terminal());
//! assert!(state.can_transition_to(&DKGState::Round1Commitment));
//!
//! // Create Round1Package
//! let participant = ParticipantId::new();
//! let commitment = [0x42u8; 32];
//! let proof = [0xABu8; 64];
//! let package = Round1Package::new(participant, commitment, proof);
//!
//! // Verify proof (stub - always true for now)
//! assert!(package.verify_proof());
//! ```

pub mod packages;
pub mod session;
pub mod state;

pub use packages::{Round1Package, Round2Package};
pub use session::{DKGSession, DKGSessionConfig};
pub use state::DKGState;