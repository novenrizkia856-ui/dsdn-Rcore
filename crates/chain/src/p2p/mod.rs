//! # DSDN P2P Network Layer
//!
//! Module ini menyediakan abstraksi P2P networking untuk DSDN chain.
//! Dirancang sebagai fondasi yang **bekerja sekarang** dan **ready untuk
//! Tahap 28 (Bootstrap Network System)** tanpa breaking changes.
//!
//! ## Arsitektur
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                     PeerManager                         │
//! │  (orchestrator: scoring, rotation, eviction, discovery) │
//! └────┬──────────┬───────────┬──────────┬─────────────────┘
//!      │          │           │          │
//!      ▼          ▼           ▼          ▼
//! ┌────────┐ ┌──────────┐ ┌─────────┐ ┌──────────┐
//! │PeerStore│ │Handshake │ │   PEX   │ │Bootstrap │
//! │(peers. │ │Protocol  │ │Exchange │ │  Config  │
//! │  dat)  │ │          │ │         │ │(DNS/IP)  │
//! └────────┘ └──────────┘ └─────────┘ └──────────┘
//! ```
//!
//! ## Komponen
//!
//! | Module | Fungsi |
//! |--------|--------|
//! | `identity` | Network ID, Node ID, Protocol Version |
//! | `types` | PeerEntry, ServiceType, PeerSource |
//! | `config` | BootstrapConfig, DnsSeed, StaticPeer |
//! | `scoring` | Peer scoring & selection algorithm |
//! | `store` | Persistent peer cache (peers.dat) |
//! | `handshake` | Peer handshake protocol messages |
//! | `pex` | Peer Exchange (PEX) protocol |
//! | `manager` | PeerManager orchestrator |
//!
//! ## Desain Prinsip
//!
//! 1. **Transport-agnostic** — Module ini TIDAK implement TCP/QUIC.
//!    Ia mengelola *logic* peer lifecycle. Transport di-plug di Tahap 28.
//!
//! 2. **Backward-compatible** — BroadcastManager/PeerInfo di rpc.rs
//!    tetap bekerja. Module ini bridge antara legacy dan sistem baru.
//!
//! 3. **Fallback chain** — Bootstrap mengikuti urutan:
//!    `peers.dat → static IP → DNS seed → retry`
//!
//! 4. **Deterministic scoring** — Peer scoring formula deterministik.

pub mod identity;
pub mod types;
pub mod config;
pub mod scoring;
pub mod store;
pub mod handshake;
pub mod pex;
pub mod manager;

// ════════════════════════════════════════════════════════════════════════════
// RE-EXPORTS
// ════════════════════════════════════════════════════════════════════════════

pub use identity::{NetworkId, NodeId, ProtocolVersion, CURRENT_PROTOCOL_VERSION};
pub use types::{PeerEntry, PeerStatus, ServiceType, PeerSource};
pub use config::{BootstrapConfig, DnsSeed, StaticPeer, ConnectionLimits};
pub use scoring::{PeerScorer, PeerScore};
pub use store::PeerStore;
pub use handshake::{HandshakeMessage, HandshakeResult, HandshakeError};
pub use pex::{PexRequest, PexResponse, PexConfig};
pub use manager::PeerManager;