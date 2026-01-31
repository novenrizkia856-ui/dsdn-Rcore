//! Multi-Coordinator Module (14A.2B.2.11, 14A.2B.2.12, 14A.2B.2.13, 14A.2B.2.14, 14A.2B.2.15)
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
//! ## Base Types (14A.2B.2.11)
//!
//! - **CoordinatorId** - Identifier unik untuk setiap coordinator
//! - **KeyShare** - Key share untuk threshold signing
//! - **SessionId** - Identifier untuk signing sessions
//! - **WorkloadId** - Identifier untuk workloads
//! - **Vote** - Coordinator vote untuk receipt approval
//! - **PendingReceipt** - Receipt yang menunggu quorum votes
//!
//! ## Peer Management (14A.2B.2.12)
//!
//! - **ConnectionState** - State koneksi peer
//! - **PeerConnection** - Data koneksi untuk satu peer
//! - **PeerConfig** - Konfigurasi peer management
//! - **PeerManager** - Manager untuk peer connections
//!
//! ## Messaging (14A.2B.2.13)
//!
//! - **CoordinatorMessage** - Enum pesan untuk komunikasi coordinator-to-coordinator
//! - **MessageVote** - Vote decision (Approve/Reject)
//! - **MessageDecodeError** - Error type untuk decode failures
//!
//! ## Network (14A.2B.2.14)
//!
//! - **CoordinatorNetwork** - Async trait untuk network operations
//! - **NetworkError** - Error type untuk network failures
//! - **MockNetwork** - In-memory mock implementation untuk testing
//!
//! ## Consensus (14A.2B.2.15)
//!
//! - **ReceiptConsensus** - State machine untuk consensus satu receipt
//! - **ConsensusState** - State dalam consensus lifecycle
//! - **ConsensusError** - Error type untuk consensus failures
//! - **StateTransition** - Hasil dari add_vote operation
//!
//! # Usage
//!
//! ```ignore
//! use dsdn_coordinator::multi::{
//!     CoordinatorId, SessionId, WorkloadId, Vote, PendingReceipt,
//!     ConnectionState, PeerConnection, PeerConfig, PeerManager,
//!     CoordinatorMessage, MessageVote,
//!     CoordinatorNetwork, NetworkError, MockNetwork,
//!     ReceiptConsensus, ConsensusState, ConsensusError, StateTransition,
//! };
//!
//! // Create coordinator identity
//! let coord_id = CoordinatorId::new([0x01; 32]);
//!
//! // Generate unique session
//! let session_id = SessionId::generate();
//!
//! // Setup peer management
//! let config = PeerConfig::new(5000, 3, 1000)?;
//! let mut manager = PeerManager::new(config);
//! manager.add_peer(coord_id.clone(), "192.168.1.1:8080".to_string());
//! manager.mark_seen(&coord_id);
//!
//! // Send messages via network
//! let network = MockNetwork::new(coord_id.clone());
//! let ping = CoordinatorMessage::ping_now();
//! network.broadcast(ping).await?;
//!
//! // Run consensus
//! let mut consensus = ReceiptConsensus::new(
//!     workload_id, receipt_data, proposer_id, 3, 30000, now_ms,
//! );
//! let transition = consensus.add_vote(voter_id, vote, now_ms);
//! ```

mod types;
mod peer;
mod message;
mod network;
mod consensus;

// Re-export all public types from types module (14A.2B.2.11)
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

// Re-export all public types from peer module (14A.2B.2.12)
pub use peer::{
    // Connection state
    ConnectionState,
    PeerConnection,

    // Configuration
    PeerConfig,
    PeerConfigError,

    // Manager
    PeerManager,
};

// Re-export all public types from message module (14A.2B.2.13)
pub use message::{
    // Message enum
    CoordinatorMessage,

    // Vote decision
    MessageVote,

    // Error types
    MessageDecodeError,
};

// Re-export all public types from network module (14A.2B.2.14)
pub use network::{
    // Trait
    CoordinatorNetwork,

    // Error type
    NetworkError,

    // Mock implementation
    MockNetwork,
};

// Re-export all public types from consensus module (14A.2B.2.15)
pub use consensus::{
    // State machine
    ReceiptConsensus,

    // State enum
    ConsensusState,

    // Error type
    ConsensusError,

    // Transition result
    StateTransition,
};