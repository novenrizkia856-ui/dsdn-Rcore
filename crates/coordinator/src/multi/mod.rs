//! Multi-Coordinator Module (14A.2B.2.11, 14A.2B.2.12, 14A.2B.2.13, 14A.2B.2.14, 14A.2B.2.15, 14A.2B.2.16, 14A.2B.2.17, 14A.2B.2.18, 14A.2B.2.19, 14A.2B.2.20)
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
//! ## Consensus (14A.2B.2.15, 14A.2B.2.16)
//!
//! - **ReceiptConsensus** - State machine untuk consensus satu receipt
//! - **ConsensusState** - State dalam consensus lifecycle
//! - **ConsensusError** - Error type untuk consensus failures
//! - **StateTransition** - Record transisi state yang auditable (struct)
//! - **TransitionTrigger** - Enum trigger yang menyebabkan transisi
//! - **AddVoteResult** - Hasil dari operasi add_vote
//!
//! ## Handlers (14A.2B.2.17)
//!
//! - **MultiCoordinatorState** - State untuk multi-coordinator consensus
//! - **HandlerError** - Error type untuk handler failures
//! - **ValidationError** - Error type untuk validation failures
//! - **handle_propose_receipt** - Handler untuk ProposeReceipt message
//! - **handle_vote_receipt** - Handler untuk VoteReceipt message
//! - **validate_receipt_proposal** - Validasi receipt proposal data
//! - **create_vote_response** - Membuat vote response message
//!
//! ## Signing (14A.2B.2.18)
//!
//! - **SigningSession** - State machine untuk signing session
//! - **SigningState** - State dalam signing session lifecycle
//! - **SigningError** - Error type untuk signing failures
//! - **handle_signing_commitment** - Handler untuk SigningCommitment message
//! - **handle_partial_signature** - Handler untuk PartialSignature message
//! - **initiate_signing_session** - Memulai signing session setelah voting threshold
//!
//! ## Optimistic Receipt (14A.2B.2.19)
//!
//! - **OptimisticReceipt** - Low-latency receipt dengan single signature
//! - **OptimisticReceiptError** - Error type untuk optimistic receipt operations
//! - **create_placeholder_signature** - Helper untuk testing
//!
//! ## MultiCoordinator (14A.2B.2.20)
//!
//! - **MultiCoordinator** - Main entry point untuk multi-coordinator consensus
//! - **MultiCoordinatorConfig** - Configuration struct
//! - **MultiCoordinatorError** - Error type untuk construction failures
//! - **ConfigError** - Error type untuk config validation
//!
//! # Usage
//!
//! ```ignore
//! use dsdn_coordinator::multi::{
//!     CoordinatorId, SessionId, WorkloadId, Vote, PendingReceipt,
//!     ConnectionState, PeerConnection, PeerConfig, PeerManager,
//!     CoordinatorMessage, MessageVote,
//!     CoordinatorNetwork, NetworkError, MockNetwork,
//!     ReceiptConsensus, ConsensusState, ConsensusError,
//!     StateTransition, TransitionTrigger, AddVoteResult,
//!     MultiCoordinatorState, HandlerError, handle_propose_receipt,
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
//! // Run consensus with explicit state transitions
//! let mut consensus = ReceiptConsensus::new(
//!     workload_id, receipt_data, proposer_id, 3, 30000, now_ms,
//! );
//! let transition = consensus.transition_to_voting()?;
//! let result = consensus.add_vote(voter_id, vote, now_ms);
//! let transition = consensus.transition_to_signing(session_id)?;
//! let transition = consensus.complete_signing(receipt)?;
//!
//! // Handle messages with handlers
//! let mut state = MultiCoordinatorState::new(self_id, committee, 2, 30000);
//! let response = handle_propose_receipt(&mut state, session_id, data, proposer, now_ms)?;
//! ```

mod types;
mod peer;
mod message;
mod network;
mod consensus;
mod handlers;
mod signing;
mod optimistic;
mod coordinator;
pub mod receipt_signing;
pub mod receipt_trigger;
pub mod receipt_assembler;

// Mock TSS for testing only (CO.7)
// NEVER available in default production build.
#[cfg(any(test, feature = "mock-tss"))]
pub mod mock_tss;

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

// Re-export all public types from consensus module (14A.2B.2.15, 14A.2B.2.16)
pub use consensus::{
    // State machine
    ReceiptConsensus,

    // State enum
    ConsensusState,

    // Error type
    ConsensusError,

    // Transition types (14A.2B.2.16)
    StateTransition,
    TransitionTrigger,

    // Add vote result (renamed from StateTransition enum)
    AddVoteResult,
};

// Re-export all public types from handlers module (14A.2B.2.17, CO.8)
pub use handlers::{
    // State
    MultiCoordinatorState,

    // Error types
    HandlerError,
    ValidationError,

    // Receipt signing lifecycle errors (CO.8)
    RegisterError,
    CompleteError,

    // Handler functions
    handle_propose_receipt,
    handle_vote_receipt,
    handle_message,

    // Signing handlers (14A.2B.2.18)
    handle_signing_commitment,
    handle_partial_signature,
    initiate_signing_session,

    // Helper functions
    validate_receipt_proposal,
    create_vote_response,
};

// Re-export all public types from signing module (14A.2B.2.18)
pub use signing::{
    // Session
    SigningSession,

    // State
    SigningState,

    // Error type
    SigningError,

    // Helper functions
    derive_session_id,
    validate_commitment,
    validate_partial,
};

// Re-export all public types from optimistic module (14A.2B.2.19)
pub use optimistic::{
    // Receipt
    OptimisticReceipt,

    // Error type
    OptimisticReceiptError,

    // Helper functions
    create_placeholder_signature,
};

// Re-export all public types from coordinator module (14A.2B.2.20)
pub use coordinator::{
    // Main struct
    MultiCoordinator,

    // Config
    MultiCoordinatorConfig,

    // Error types
    MultiCoordinatorError,
    ConfigError,
};

// Re-export all public types from receipt_signing module (CO.1)
pub use receipt_signing::{
    // Session
    ReceiptSigningSession,

    // Type alias
    ReceiptTypeProto,

    // Constants
    RECEIPT_TYPE_STORAGE,
    RECEIPT_TYPE_COMPUTE,
};

// Re-export all public types from receipt_trigger module (CO.4)
pub use receipt_trigger::{
    // Trigger function
    trigger_receipt_signing,

    // Context struct
    ReceiptContext,

    // Error type
    ReceiptTriggerError,
};

// Re-export all public types from receipt_assembler module (CO.5)
pub use receipt_assembler::{
    // Assembly function
    assemble_signed_receipt,

    // Validation function
    validate_receipt_proto,

    // Error type
    AssemblyError,
};