//! Coordinator integration module (14A.2B.2.21)
//!
//! Module struktur untuk integrasi coordinator ↔ chain layer.

pub mod types;
pub mod epoch;
pub mod dkg;
pub mod disputes;
pub mod accountability;

pub use types::{CommitteeStatus, CommitteeTransition, EpochConfig};
pub use epoch::EpochManager;
pub use dkg::{DKGError, EpochDKG, EpochDKGState};
pub use disputes::*;
pub use accountability::*;