//! Multi-Coordinator Module (14A.2B.2.11)
//!
//! Module ini menyediakan types dan utilities untuk sistem multi-coordinator
//! dalam DSDN.
//!
//! # Overview
//!
//! Multi-coordinator architecture memungkinkan beberapa coordinator instance
//! berjalan secara paralel untuk mengurangi single point of failure dan
//! meningkatkan fault tolerance.
//!
//! # Components
//!
//! - **CoordinatorId** - Identifier unik untuk setiap coordinator
//! - **KeyShare** - Key share untuk threshold signing
//! - **SessionId** - Identifier untuk signing sessions
//! - **WorkloadId** - Identifier untuk workloads
//! - **Vote** - Coordinator vote untuk receipt approval
//! - **PendingReceipt** - Receipt yang menunggu quorum votes
//!
//! # Usage
//!
//! ```ignore
//! use dsdn_coordinator::multi::{
//!     CoordinatorId, SessionId, WorkloadId, Vote, PendingReceipt,
//! };
//!
//! // Create coordinator identity
//! let coord_id = CoordinatorId::new([0x01; 32]);
//!
//! // Generate unique session
//! let session_id = SessionId::generate()?;
//!
//! // Cast vote
//! let vote = Vote::new(true, timestamp, signature);
//! ```

mod types;

// Re-export all public types
pub use types::{
    // Identity types
    CoordinatorId,
    SessionId,
    WorkloadId,

    // Key management
    KeyShare,

    // Voting
    Vote,
    PendingReceipt,
};

