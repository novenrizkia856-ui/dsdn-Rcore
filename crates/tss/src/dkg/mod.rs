//! # DKG (Distributed Key Generation) Module
//!
//! Module ini menyediakan types untuk Distributed Key Generation protocol
//! dalam FROST Threshold Signature Scheme, menggunakan real FROST DKG
//! dari `frost-ed25519` (ZCash Foundation).
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
//! ## Implementasi Kriptografi
//!
//! DKG menggunakan **Pedersen DKG (Feldman VSS variant)** dari `frost-ed25519`:
//!
//! ### Round 1: Commitment Phase (`frost::keys::dkg::part1`)
//!
//! 1. Setiap participant generate random polynomial derajat t-1
//! 2. Participant broadcast `Round1Package` berisi:
//!    - Feldman VSS commitments: t compressed Edwards Y curve points
//!    - Schnorr proof of knowledge of constant term
//! 3. frost library memverifikasi semua commitments dan proofs
//!
//! ### Round 2: Share Distribution (`frost::keys::dkg::part2`)
//!
//! 1. Setiap participant mengevaluasi polynomialnya di titik setiap peer
//! 2. `Round2Package` berisi polynomial evaluation (secret share) per recipient
//! 3. frost library memverifikasi shares terhadap VSS commitments dari Round 1
//!
//! ### Completion (`frost::keys::dkg::part3`)
//!
//! Jika semua shares valid:
//! - Setiap participant menghitung final `SigningShare`
//! - Group `VerifyingKey` dihitung dari semua commitments
//! - State menjadi `Completed` dengan `KeyShare`
//!
//! Output kompatibel untuk `frost-ed25519` threshold signing.
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
//! ## Contoh Penggunaan
//!
//! ```rust
//! use dsdn_tss::dkg::{DKGState, LocalDKGParticipant, DKGParticipant};
//! use dsdn_tss::{ParticipantId, SessionId};
//!
//! // Create initial state
//! let state = DKGState::Initialized;
//! assert!(!state.is_terminal());
//! assert!(state.can_transition_to(&DKGState::Round1Commitment));
//!
//! // Create a DKG participant for a 2-of-3 scheme
//! let session_id = SessionId::new();
//! let participant_id = ParticipantId::new();
//! let mut participant = LocalDKGParticipant::new(
//!     participant_id, session_id, 2, 3,
//! ).unwrap();
//!
//! // Generate Round 1 package (wraps frost::keys::dkg::part1)
//! let round1_package = participant.generate_round1().unwrap();
//! ```

pub mod packages;
pub mod participant;
pub mod session;
pub mod state;

pub use packages::{Round1Package, Round2Package};
pub use participant::{DKGParticipant, KeyShare, LocalDKGParticipant, LocalParticipantState};
pub use session::{DKGSession, DKGSessionConfig};
pub use state::DKGState;