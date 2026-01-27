//! # DSDN Common Crate
//!
//! Crate ini menyediakan abstraksi Data Availability (DA) Layer dan utilities
//! untuk DSDN (Distributed Storage and Data Network).
//!
//! ## Peran Crate
//!
//! `dsdn-common` adalah foundation crate yang menyediakan:
//! - Abstraksi DA Layer untuk multiple backends (Celestia, Validator Quorum, Foundation)
//! - Health monitoring untuk DA endpoints
//! - Routing deterministik dengan fallback hierarchy
//! - Cryptographic utilities
//! - Content addressing (CID)
//! - Configuration management
//! - Multi-coordinator committee management dengan TSS support
//!
//! ## Arsitektur Fallback & DA Routing
//!
//! DSDN menggunakan multi-tier DA architecture untuk high availability:
//!
//! | Tier | DA Layer | Kondisi Penggunaan |
//! |------|----------|-------------------|
//! | Primary | Celestia | Status Healthy/Warning/Recovering |
//! | Secondary | Validator Quorum | Status Degraded (fallback level-1) |
//! | Emergency | Foundation | Status Emergency (fallback level-2) |
//!
//! ### Routing Diagram
//!
//! ```text
//! ┌─────────────────┐
//! │    DARouter     │  <- Routing abstraction
//! └────────┬────────┘
//!          │
//! ┌─────┴─────┬─────────────┐
//! │           │             │
//! ┌──▼──┐    ┌───▼───┐    ┌────▼────┐
//! │Celestia│ │QuorumDA│   │EmergencyDA│
//! │(Primary)│ │(Secondary)│ │(Foundation)│
//! └────────┘ └─────────┘   └───────────┘
//! ```
//!
//! ## Coordinator Committee System
//!
//! DSDN menggunakan committee of coordinators untuk threshold signing.
//! Committee beroperasi dalam epoch-based rotation dengan handoff mechanism.
//!
//! ### Committee Lifecycle
//!
//! ```text
//! Initializing → Active → InHandoff → Active (new epoch)
//!                  ↓           ↓
//!               Expire      Expire
//!                  ↓           ↓
//!               Expired     Expired
//! ```
//!
//! ### Coordinator Types
//!
//! | Type | Description |
//! |------|-------------|
//! | `CoordinatorId` | 32-byte unique identifier |
//! | `CoordinatorMember` | Member dengan pubkey dan stake |
//! | `CoordinatorCommittee` | Committee dengan threshold signing |
//! | `ThresholdReceipt` | Receipt dengan aggregate signature |
//! | `CommitteeTransition` | Epoch rotation dengan handoff |
//! | `CommitteeStatus` | Lifecycle status tracking |
//!
//! ## Komponen Utama
//!
//! ### DAHealthMonitor
//!
//! Thread-safe health monitor yang melacak status DA endpoint.
//! Menyediakan `DAStatus` yang menentukan routing decision.
//!
//! Status yang di-track:
//! - `Healthy`: Primary DA beroperasi normal
//! - `Warning`: Primary DA mengalami latency tinggi
//! - `Degraded`: Primary DA tidak tersedia, gunakan secondary
//! - `Emergency`: Kondisi kritis, gunakan emergency DA
//! - `Recovering`: Primary DA sedang recovery dari degraded/emergency
//!
//! ### DARouter
//!
//! Routing abstraction yang menentukan DA target berdasarkan status kesehatan.
//! Keputusan routing bersifat deterministik berdasarkan `DAStatus` dari
//! `DAStatusProvider` (biasanya `DAHealthMonitor`).
//!
//! Behavior per status:
//! - `Healthy/Warning/Recovering`: Route ke primary (Celestia)
//! - `Degraded`: Route ke secondary, tag blob sebagai `PendingReconcile`
//! - `Emergency`: Route ke emergency, tag blob sebagai `EmergencyPending`
//!
//! ### DALayer Trait
//!
//! Abstraksi untuk DA backend. Implementasi yang tersedia:
//! - `CelestiaDA`: Production implementation untuk Celestia
//! - `MockDA`: Testing implementation
//!
//! ## Usage Patterns
//!
//! ### Basic DA Operations
//!
//! ```rust,ignore
//! use dsdn_common::{DALayer, CelestiaDA};
//!
//! // Initialize DA layer
//! let da = CelestiaDA::from_env()?;
//!
//! // Post blob
//! let blob_ref = da.post_blob(data).await?;
//!
//! // Get blob
//! let blob = da.get_blob(&blob_ref).await?;
//! ```
//!
//! ### Using DARouter with Health Monitoring
//!
//! ```rust,ignore
//! use dsdn_common::{DARouter, DARouterConfig, DARouterMetrics, DAHealthMonitor};
//! use std::sync::Arc;
//!
//! // Setup health monitor sebagai status provider
//! let health_monitor = Arc::new(DAHealthMonitor::new(config));
//!
//! // Setup router dengan fallback hierarchy
//! let metrics = Arc::new(DARouterMetrics::new());
//! let router = DARouter::new(primary_da, health_monitor, DARouterConfig::new(), metrics)
//!     .with_fallbacks(Some(secondary_da), Some(emergency_da));
//!
//! // Router akan memilih DA target berdasarkan status
//! let blob_ref = router.post_blob(data).await?;
//! ```
//!
//! ### Coordinator Committee Operations
//!
//! ```rust,ignore
//! use dsdn_common::{
//!     CoordinatorCommittee, CoordinatorMember, CoordinatorId,
//!     ThresholdReceipt, CommitteeStatus,
//! };
//!
//! // Create committee
//! let committee = CoordinatorCommittee::new(
//!     members, threshold, epoch, epoch_start, duration, group_pubkey
//! )?;
//!
//! // Verify receipt
//! if receipt.verify(&committee) {
//!     // Receipt valid
//! }
//!
//! // Track status
//! let status = CommitteeStatus::active(committee, timestamp);
//! if status.can_accept_receipts() {
//!     // Process receipts
//! }
//! ```
//!
//! ### Fallback Activation
//!
//! Fallback diaktifkan ketika:
//! 1. `DAHealthMonitor` melaporkan status `Degraded` atau `Emergency`
//! 2. `DARouterConfig.enable_fallback` adalah `true` (default)
//! 3. Fallback DA tersedia (dikonfigurasi via `with_fallbacks`)
//!
//! Blob yang ditulis ke fallback akan di-tag untuk reconciliation ketika
//! primary DA kembali sehat.
//!
//! ## Batasan (Non-Goals)
//!
//! Crate ini TIDAK menyediakan:
//! - Automatic reconciliation (hanya tagging, eksekusi di layer lain)
//! - Network transport atau gRPC endpoints
//! - Consensus atau finality guarantees
//! - Persistent storage (in-memory state only)
//! - Rate limiting atau throttling
//!
//! ## Modules
//!
//! | Module | Deskripsi |
//! |--------|-----------|
//! | `da` | DALayer trait definition dan types |
//! | `celestia_da` | Celestia DA implementation |
//! | `mock_da` | Mock implementation for testing |
//! | `da_health_monitor` | Thread-safe DA health monitoring |
//! | `da_router` | DA routing dengan fallback hierarchy |
//! | `crypto` | Cryptographic utilities |
//! | `cid` | Content addressing utilities |
//! | `config` | Configuration management |
//! | `consistent_hash` | Consistent hashing for placement |
//! | `coordinator` | Multi-coordinator committee management dengan TSS | |

// ════════════════════════════════════════════════════════════════════════════════
// MODULE DECLARATIONS
// ════════════════════════════════════════════════════════════════════════════════

// Core utilities
pub mod crypto;
pub mod cid;
pub mod config;
pub mod consistent_hash;

// DA Layer abstraction
pub mod da;
pub mod celestia_da;
pub mod mock_da;

// DA Health & Routing (14A.1A.11 - 14A.1A.19)
pub mod da_health_monitor;
pub mod da_router;

// Coordinator types (14A.2B.1.11)
pub mod coordinator;

// ════════════════════════════════════════════════════════════════════════════════
// PUBLIC API EXPORTS
// ════════════════════════════════════════════════════════════════════════════════

// DA Layer types
pub use da::{DALayer, DAError, DAHealthStatus, BlobRef, Blob, BlobStream, DAConfig};

// DA Layer implementations
pub use celestia_da::CelestiaDA;
pub use mock_da::MockDA;

// DA Health Monitor types (14A.1A.11)
pub use da_health_monitor::{DAHealthMonitor, DAStatus, DAHealthConfig};

// DA Router types (14A.1A.15 - 14A.1A.19)
pub use da_router::{
    DARouter,
    DARouterConfig,
    DARouterMetrics,
    DAStatusProvider,
    ReconcileTag,
    MetricsSnapshot,
};

// Coordinator types (14A.2B.1.11)
pub use coordinator::*;

// ════════════════════════════════════════════════════════════════════════════════
// COMMON TYPES
// ════════════════════════════════════════════════════════════════════════════════

/// Common Result type untuk crate ini.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;