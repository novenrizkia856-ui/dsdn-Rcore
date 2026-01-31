//! Multi-Coordinator Module (14A.2B.2.11, 14A.2B.2.12)
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
//! # Usage
//!
//! ```ignore
//! use dsdn_coordinator::multi::{
//!     CoordinatorId, SessionId, WorkloadId, Vote, PendingReceipt,
//!     ConnectionState, PeerConnection, PeerConfig, PeerManager,
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
//! // Get healthy peers
//! let healthy = manager.get_healthy_peers();
//! ```

mod types;
mod peer;

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