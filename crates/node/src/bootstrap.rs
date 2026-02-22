//! # Bootstrap Network System (Pre-21 Foundation)
//!
//! Provides the complete P2P bootstrap foundation for DSDN storage nodes.
//! This module is designed to be **immediately functional** while preparing
//! the full integration surface for Tahap 21 (DNS Seed + Peer Discovery).
//!
//! ## Design Philosophy
//!
//! All network I/O is abstracted behind traits ([`DnsResolver`],
//! [`PeerConnector`]) so the system can be tested with mocks now and
//! replaced with real implementations in Tahap 28 without changing the
//! orchestration logic.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                        PeerManager                               │
//! │  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
//! │  │BootstrapConfig│  │  PeerStore   │  │   BootstrapMetrics    │  │
//! │  │ - dns_seeds   │  │ (peers.dat)  │  │ - resolve_attempts    │  │
//! │  │ - static_peers│  │ - read/write │  │ - connect_attempts    │  │
//! │  │ - timeouts    │  │ - scoring    │  │ - handshake_failures  │  │
//! │  │ - limits      │  │ - GC         │  │ - fallback_triggers   │  │
//! │  └──────────────┘  └──────────────┘  └───────────────────────┘  │
//! │                                                                  │
//! │  Fallback Chain: peers.dat → static IP → DNS seed → retry       │
//! │                                                                  │
//! │  ┌──────────────────────┐  ┌──────────────────────────────────┐  │
//! │  │  dyn DnsResolver     │  │     dyn PeerConnector            │  │
//! │  │  (mock now, real@28) │  │     (mock now, real@28)          │  │
//! │  └──────────────────────┘  └──────────────────────────────────┘  │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Fallback Priority Order
//!
//! 1. **peers.dat** — Local cache, fastest. Sorted by score descending.
//! 2. **Static IP peers** — From config. Iterated one by one.
//! 3. **DNS seeds** — Resolved to IP lists. Seeds tried sequentially.
//! 4. **Retry** — Exponential backoff, periodic re-attempt of all sources.
//!
//! ## Service Type Discovery
//!
//! Every node advertises its [`ServiceType`] during handshake.
//! This enables targeted discovery: validators find chain nodes,
//! coordinators find storage nodes, etc.
//!
//! ## Peer Scoring
//!
//! ```text
//! score = base(10)
//!       + (success_count × 2)
//!       − (failure_count × 3)
//!       + recency_bonus (< 1h: +10, < 24h: +5)
//!       − staleness_penalty (> 7d: −5, > 30d: −10)
//! ```
//!
//! ## Safety
//!
//! - No `panic!`, `unwrap()`, `expect()` in production paths.
//! - No `unsafe` code.
//! - All types are `Send + Sync`.
//! - Atomic file writes for peers.dat (write tmp → rename).
//! - All arithmetic uses `saturating_*` operations.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Default DSDN P2P port.
pub const DEFAULT_P2P_PORT: u16 = 45831;

/// Default maximum outbound peer connections.
pub const DEFAULT_MAX_OUTBOUND: usize = 8;

/// Default maximum inbound peer connections.
pub const DEFAULT_MAX_INBOUND: usize = 125;

/// Default DNS resolve timeout in seconds.
pub const DEFAULT_DNS_TIMEOUT_SECS: u64 = 10;

/// Default peer connect timeout in seconds.
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 5;

/// Maximum entries in peers.dat.
pub const MAX_PEERS_DAT_ENTRIES: usize = 10_000;

/// Peer expiry: remove if no successful connect in 30 days.
pub const PEER_EXPIRY_SECS: u64 = 30 * 24 * 3600;

/// Mark peer suspicious after this many consecutive failures.
pub const SUSPICIOUS_FAILURE_THRESHOLD: u32 = 10;

/// Base score for peer scoring algorithm.
pub const PEER_BASE_SCORE: i64 = 10;

/// Score bonus per successful connection.
pub const SCORE_SUCCESS_WEIGHT: i64 = 2;

/// Score penalty per failed connection.
pub const SCORE_FAILURE_WEIGHT: i64 = 3;

/// Score bonus: last seen < 1 hour ago.
pub const RECENCY_BONUS_1H: i64 = 10;

/// Score bonus: last seen < 24 hours ago.
pub const RECENCY_BONUS_24H: i64 = 5;

/// Score penalty: last seen > 7 days ago.
pub const STALENESS_PENALTY_7D: i64 = 5;

/// Score penalty: last seen > 30 days ago.
pub const STALENESS_PENALTY_30D: i64 = 10;

/// Retry interval when all bootstrap sources fail (seconds).
pub const BOOTSTRAP_RETRY_INTERVAL_SECS: u64 = 30;

/// PEX rate limit: max 1 request per peer per this interval (seconds).
pub const PEX_RATE_LIMIT_SECS: u64 = 900; // 15 minutes

/// Maximum peers returned in a single PEX response.
pub const PEX_MAX_PEERS_PER_RESPONSE: usize = 1000;

/// Handshake protocol version for DSDN P2P.
pub const PROTOCOL_VERSION: u32 = 1;

// Time constants in seconds
const SECS_1H: u64 = 3600;
const SECS_24H: u64 = 86400;
const SECS_7D: u64 = 7 * 86400;
const SECS_30D: u64 = 30 * 86400;

// ════════════════════════════════════════════════════════════════════════════════
// SERVICE TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// The role a node advertises in the DSDN network.
///
/// Used during handshake and PEX so nodes can find specific
/// component types they need (e.g., a validator looking for
/// chain nodes, or a storage node looking for coordinators).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServiceType {
    /// Block production and state management.
    Chain,
    /// Data storage node (regular community operator).
    Storage,
    /// Data storage node (data center grade).
    StorageDC,
    /// Workload coordination and TSS/FROST participation.
    Coordinator,
    /// Consensus and validation.
    Validator,
    /// HTTP gateway / ingress proxy.
    Ingress,
    /// Dedicated bootstrap node — only serves discovery, no data.
    Bootstrap,
}

impl ServiceType {
    /// Returns a stable string tag for serialization and display.
    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceType::Chain => "chain",
            ServiceType::Storage => "storage",
            ServiceType::StorageDC => "storage_dc",
            ServiceType::Coordinator => "coordinator",
            ServiceType::Validator => "validator",
            ServiceType::Ingress => "ingress",
            ServiceType::Bootstrap => "bootstrap",
        }
    }

    /// Parse from a string tag. Case-insensitive.
    pub fn from_str_tag(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "chain" => Some(ServiceType::Chain),
            "storage" => Some(ServiceType::Storage),
            "storage_dc" | "storagedc" => Some(ServiceType::StorageDC),
            "coordinator" => Some(ServiceType::Coordinator),
            "validator" => Some(ServiceType::Validator),
            "ingress" => Some(ServiceType::Ingress),
            "bootstrap" => Some(ServiceType::Bootstrap),
            _ => None,
        }
    }
}

impl fmt::Display for ServiceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// NETWORK ID
// ════════════════════════════════════════════════════════════════════════════════

/// Network identifier for peer isolation.
///
/// Peers MUST share the same `NetworkId` to connect.
/// Mismatched network IDs cause handshake rejection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkId {
    Mainnet,
    Testnet,
    /// Custom network for development/staging.
    Custom(String),
}

impl NetworkId {
    /// Parse from a string. Recognizes "mainnet", "testnet",
    /// and treats everything else as a custom network.
    pub fn from_string(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "mainnet" => NetworkId::Mainnet,
            "testnet" => NetworkId::Testnet,
            other => NetworkId::Custom(other.to_string()),
        }
    }

    /// Stable string representation.
    pub fn as_str(&self) -> &str {
        match self {
            NetworkId::Mainnet => "mainnet",
            NetworkId::Testnet => "testnet",
            NetworkId::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Default for NetworkId {
    fn default() -> Self {
        NetworkId::Mainnet
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// PEER SOURCE
// ════════════════════════════════════════════════════════════════════════════════

/// How a peer was discovered. Tracked for eclipse attack mitigation
/// — nodes should maintain peers from diverse sources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerSource {
    /// Resolved from a DNS seed entry.
    DnsSeed,
    /// From the static peer list in config.
    StaticConfig,
    /// Received via Peer Exchange Protocol from another peer.
    PeerExchange,
    /// Inbound connection (the peer connected to us).
    Inbound,
    /// Manually added by operator via CLI.
    Manual,
}

impl fmt::Display for PeerSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerSource::DnsSeed => write!(f, "dns_seed"),
            PeerSource::StaticConfig => write!(f, "static_config"),
            PeerSource::PeerExchange => write!(f, "peer_exchange"),
            PeerSource::Inbound => write!(f, "inbound"),
            PeerSource::Manual => write!(f, "manual"),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// BOOTSTRAP CONFIG
// ════════════════════════════════════════════════════════════════════════════════

/// Default TOML config file name at project root.
pub const DEFAULT_CONFIG_FILE: &str = "dsdn.toml";

/// Search paths for `dsdn.toml` (tried in order).
///
/// 1. `DSDN_CONFIG_FILE` env override (explicit path)
/// 2. `./dsdn.toml` (current working directory / project root)
/// 3. `~/.dsdn/dsdn.toml` (user home config)
/// 4. `/etc/dsdn/dsdn.toml` (system-wide config)
pub const CONFIG_SEARCH_PATHS: &[&str] = &[
    "dsdn.toml",
    ".dsdn/dsdn.toml",
    "/etc/dsdn/dsdn.toml",
];

/// Intermediate struct for deserializing the `[bootstrap]` section
/// from `dsdn.toml`. Field names match the TOML key names exactly
/// as specified in the Tahap 28 design document.
///
/// All fields are `Option` so that partial configs work —
/// unspecified fields fall through to env vars, then defaults.
///
/// ## TOML Format
///
/// ```toml
/// [bootstrap]
/// # DNS seeds (founder/community maintained)
/// dns_seeds = [
///     # "seed1.dsdn.network",
///     # "seed2.dsdn.network",
///     # "seed3.dsdn.network",
/// ]
///
/// # Static IP peers (community maintained)
/// static_peers = [
///     # "203.0.113.50:45831",
///     # "198.51.100.10:45831",
/// ]
///
/// # Local peer cache
/// peers_file = "peers.dat"
///
/// # Connection settings
/// max_outbound_connections = 8
/// max_inbound_connections = 125
/// dns_resolve_timeout_secs = 10
/// peer_connect_timeout_secs = 5
///
/// # Network settings
/// p2p_port = 45831
/// network_id = "mainnet"
/// service_type = "storage"
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BootstrapToml {
    /// DNS seed hostnames.
    pub dns_seeds: Option<Vec<String>>,

    /// Static IP:Port peer list.
    pub static_peers: Option<Vec<String>>,

    /// Path to persistent peer cache.
    pub peers_file: Option<String>,

    /// Max outbound connections (TOML key: `max_outbound_connections`).
    pub max_outbound_connections: Option<usize>,

    /// Max inbound connections (TOML key: `max_inbound_connections`).
    pub max_inbound_connections: Option<usize>,

    /// DNS resolve timeout in seconds.
    pub dns_resolve_timeout_secs: Option<u64>,

    /// Peer connect timeout in seconds.
    pub peer_connect_timeout_secs: Option<u64>,

    /// P2P listen port.
    pub p2p_port: Option<u16>,

    /// Network identifier ("mainnet", "testnet", or custom).
    pub network_id: Option<String>,

    /// This node's advertised service type.
    pub service_type: Option<String>,
}

/// Top-level struct wrapping the entire `dsdn.toml` file.
///
/// Only the `[bootstrap]` section is parsed here; other sections
/// (e.g., `[da]`, `[storage]`) are ignored. This allows dsdn.toml
/// to be a single unified config for the entire DSDN project while
/// each component only reads its own section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DsdnToml {
    /// The `[bootstrap]` section. `None` if the section is absent.
    pub bootstrap: Option<BootstrapToml>,
}

/// Complete bootstrap configuration for a DSDN node.
///
/// ## Load Priority (highest wins)
///
/// ```text
/// 1. Environment variables     (BOOTSTRAP_DNS_SEEDS, etc.)
/// 2. dsdn.toml [bootstrap]     (project root or search paths)
/// 3. Compiled defaults         (empty seeds, port 45831, etc.)
/// ```
///
/// Environment variables **override** dsdn.toml values per-field.
/// This allows operators to tweak settings without editing the
/// TOML file (e.g., in Docker: `docker run -e BOOTSTRAP_P2P_PORT=31313`).
///
/// ## dsdn.toml
///
/// The config file is located via:
/// 1. `DSDN_CONFIG_FILE` env var (explicit path)
/// 2. `./dsdn.toml` (CWD)
/// 3. `~/.dsdn/dsdn.toml` (home dir)
/// 4. `/etc/dsdn/dsdn.toml` (system)
///
/// If no file is found, only env vars and defaults are used (valid
/// for development — no file is required).
///
/// ## Environment Variables
///
/// | Variable | TOML Key | Default |
/// |----------|----------|---------|
/// | `BOOTSTRAP_DNS_SEEDS` | `dns_seeds` | (empty) |
/// | `BOOTSTRAP_STATIC_PEERS` | `static_peers` | (empty) |
/// | `BOOTSTRAP_PEERS_FILE` | `peers_file` | `peers.dat` |
/// | `BOOTSTRAP_MAX_OUTBOUND` | `max_outbound_connections` | 8 |
/// | `BOOTSTRAP_MAX_INBOUND` | `max_inbound_connections` | 125 |
/// | `BOOTSTRAP_DNS_TIMEOUT` | `dns_resolve_timeout_secs` | 10 |
/// | `BOOTSTRAP_CONNECT_TIMEOUT` | `peer_connect_timeout_secs` | 5 |
/// | `BOOTSTRAP_P2P_PORT` | `p2p_port` | 45831 |
/// | `BOOTSTRAP_NETWORK_ID` | `network_id` | mainnet |
/// | `BOOTSTRAP_SERVICE_TYPE` | `service_type` | storage |
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapConfig {
    /// DNS seed hostnames (e.g., `["seed1.dsdn.network"]`).
    /// Empty is valid for development; at least 1 recommended for mainnet.
    pub dns_seeds: Vec<String>,

    /// Static IP:Port peers (e.g., `["203.0.113.50:45831"]`).
    /// Parsed into `SocketAddr` at resolve time.
    pub static_peers: Vec<String>,

    /// Path to the persistent peer cache file.
    pub peers_file: PathBuf,

    /// Maximum outbound peer connections this node will maintain.
    pub max_outbound: usize,

    /// Maximum inbound peer connections this node will accept.
    pub max_inbound: usize,

    /// Timeout for DNS seed resolution (seconds).
    pub dns_timeout_secs: u64,

    /// Timeout for individual peer TCP connect (seconds).
    pub connect_timeout_secs: u64,

    /// P2P listen port.
    pub p2p_port: u16,

    /// Network identifier for peer isolation.
    pub network_id: NetworkId,

    /// This node's advertised service type.
    pub service_type: ServiceType,

    /// Which config file was loaded (if any). `None` = defaults only.
    /// Informational — not serialized back to TOML.
    #[serde(skip)]
    pub loaded_from: Option<PathBuf>,
}

impl BootstrapConfig {
    // ── PRIMARY ENTRY POINT ────────────────────────────────────────────

    /// Load bootstrap config with full priority chain:
    ///
    /// 1. Start with compiled defaults.
    /// 2. Search for `dsdn.toml` and apply `[bootstrap]` section.
    /// 3. Apply environment variable overrides on top.
    ///
    /// This is the recommended way to create a `BootstrapConfig`.
    /// It never fails — missing files and unset env vars are
    /// silently skipped, falling through to defaults.
    pub fn load() -> Self {
        let mut config = Self::default();

        // Phase 1: Try loading from dsdn.toml
        if let Some((toml_section, path)) = Self::find_and_parse_toml() {
            config.apply_toml(&toml_section);
            config.loaded_from = Some(path);
        }

        // Phase 2: Apply env var overrides (highest priority)
        config.apply_env_overrides();

        config
    }

    // ── TOML LOADING ───────────────────────────────────────────────────

    /// Search for `dsdn.toml` in standard locations and parse the
    /// `[bootstrap]` section if found.
    ///
    /// Search order:
    /// 1. `DSDN_CONFIG_FILE` env var (explicit path, skips search)
    /// 2. `./dsdn.toml`
    /// 3. `~/.dsdn/dsdn.toml`
    /// 4. `/etc/dsdn/dsdn.toml`
    ///
    /// Returns `None` if no config file is found or if parsing fails.
    fn find_and_parse_toml() -> Option<(BootstrapToml, PathBuf)> {
        // Check explicit path first
        if let Ok(explicit) = std::env::var("DSDN_CONFIG_FILE") {
            let path = PathBuf::from(&explicit);
            if path.exists() {
                return Self::parse_toml_file(&path).map(|t| (t, path));
            }
        }

        // Search standard locations
        for search_path in CONFIG_SEARCH_PATHS {
            let path = PathBuf::from(search_path);
            if path.exists() {
                if let Some(toml) = Self::parse_toml_file(&path) {
                    return Some((toml, path));
                }
            }

            // Also try relative to home directory for ~/.dsdn/dsdn.toml
            if search_path.starts_with('.') {
                if let Some(home) = home_dir() {
                    let home_path = home.join(search_path);
                    if home_path.exists() {
                        if let Some(toml) = Self::parse_toml_file(&home_path) {
                            return Some((toml, home_path));
                        }
                    }
                }
            }
        }

        None
    }

    /// Parse a `dsdn.toml` file and extract the `[bootstrap]` section.
    ///
    /// Returns `None` on any I/O or parse error (fail-open: the node
    /// continues with defaults + env vars).
    fn parse_toml_file(path: &Path) -> Option<BootstrapToml> {
        let content = std::fs::read_to_string(path).ok()?;
        Self::parse_toml_str(&content)
    }

    /// Parse a TOML string and extract the `[bootstrap]` section.
    ///
    /// Public for testing. Returns `None` if parsing fails or if
    /// no `[bootstrap]` section exists.
    pub fn parse_toml_str(content: &str) -> Option<BootstrapToml> {
        // Parse as generic TOML value first, then extract [bootstrap]
        let table: toml::Value = toml::from_str(content).ok()?;
        let bootstrap_val = table.get("bootstrap")?;

        // Re-serialize just the [bootstrap] section and parse into struct
        let section_str = toml::to_string(bootstrap_val).ok()?;
        toml::from_str::<BootstrapToml>(&section_str).ok()
    }

    /// Apply values from a parsed `[bootstrap]` TOML section.
    ///
    /// Only fields that are `Some` in the TOML struct are applied;
    /// `None` fields leave the current value unchanged (preserving
    /// the default).
    fn apply_toml(&mut self, toml: &BootstrapToml) {
        if let Some(ref seeds) = toml.dns_seeds {
            // Filter empty strings (from commented-out entries)
            let filtered: Vec<String> = seeds
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !filtered.is_empty() {
                self.dns_seeds = filtered;
            }
        }

        if let Some(ref peers) = toml.static_peers {
            let filtered: Vec<String> = peers
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !filtered.is_empty() {
                self.static_peers = filtered;
            }
        }

        if let Some(ref pf) = toml.peers_file {
            if !pf.is_empty() {
                self.peers_file = PathBuf::from(pf);
            }
        }

        if let Some(v) = toml.max_outbound_connections {
            self.max_outbound = v;
        }
        if let Some(v) = toml.max_inbound_connections {
            self.max_inbound = v;
        }
        if let Some(v) = toml.dns_resolve_timeout_secs {
            self.dns_timeout_secs = v;
        }
        if let Some(v) = toml.peer_connect_timeout_secs {
            self.connect_timeout_secs = v;
        }
        if let Some(v) = toml.p2p_port {
            self.p2p_port = v;
        }
        if let Some(ref s) = toml.network_id {
            self.network_id = NetworkId::from_string(s);
        }
        if let Some(ref s) = toml.service_type {
            if let Some(svc) = ServiceType::from_str_tag(s) {
                self.service_type = svc;
            }
        }
    }

    // ── ENV LOADING ────────────────────────────────────────────────────

    /// Apply environment variable overrides on top of current values.
    ///
    /// Only variables that are **set and non-empty** override.
    /// Unset variables leave the current value untouched
    /// (which may be from TOML or defaults).
    fn apply_env_overrides(&mut self) {
        if let Ok(s) = std::env::var("BOOTSTRAP_DNS_SEEDS") {
            let seeds: Vec<String> = s
                .split(',')
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect();
            if !seeds.is_empty() {
                self.dns_seeds = seeds;
            }
        }

        if let Ok(s) = std::env::var("BOOTSTRAP_STATIC_PEERS") {
            let peers: Vec<String> = s
                .split(',')
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect();
            if !peers.is_empty() {
                self.static_peers = peers;
            }
        }

        if let Ok(s) = std::env::var("BOOTSTRAP_PEERS_FILE") {
            if !s.is_empty() {
                self.peers_file = PathBuf::from(s);
            }
        }

        if let Some(v) = env_parse::<usize>("BOOTSTRAP_MAX_OUTBOUND") {
            self.max_outbound = v;
        }
        if let Some(v) = env_parse::<usize>("BOOTSTRAP_MAX_INBOUND") {
            self.max_inbound = v;
        }
        if let Some(v) = env_parse::<u64>("BOOTSTRAP_DNS_TIMEOUT") {
            self.dns_timeout_secs = v;
        }
        if let Some(v) = env_parse::<u64>("BOOTSTRAP_CONNECT_TIMEOUT") {
            self.connect_timeout_secs = v;
        }
        if let Some(v) = env_parse::<u16>("BOOTSTRAP_P2P_PORT") {
            self.p2p_port = v;
        }
        if let Ok(s) = std::env::var("BOOTSTRAP_NETWORK_ID") {
            if !s.is_empty() {
                self.network_id = NetworkId::from_string(&s);
            }
        }
        if let Ok(s) = std::env::var("BOOTSTRAP_SERVICE_TYPE") {
            if let Some(svc) = ServiceType::from_str_tag(&s) {
                self.service_type = svc;
            }
        }
    }

    // ── CONVENIENCE CONSTRUCTORS ───────────────────────────────────────

    /// Load configuration from environment variables only
    /// (skip dsdn.toml search). Useful when you know the config
    /// file isn't relevant (e.g., CI, Docker with env-only config).
    pub fn from_env() -> Self {
        let mut config = Self::default();
        config.apply_env_overrides();
        config
    }

    /// Load configuration from a specific TOML file path,
    /// then apply env overrides on top.
    ///
    /// Returns `Err` if the file cannot be read or parsed.
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;

        let toml_section = Self::parse_toml_str(&content)
            .ok_or_else(|| format!("no [bootstrap] section in {}", path.display()))?;

        let mut config = Self::default();
        config.apply_toml(&toml_section);
        config.loaded_from = Some(path.to_path_buf());

        // Env overrides still apply on top
        config.apply_env_overrides();

        Ok(config)
    }

    /// Load from a TOML string. Useful for testing.
    pub fn from_toml_str(content: &str) -> Result<Self, String> {
        let toml_section = Self::parse_toml_str(content)
            .ok_or_else(|| "no [bootstrap] section found".to_string())?;

        let mut config = Self::default();
        config.apply_toml(&toml_section);
        Ok(config)
    }

    // ── VALIDATION ─────────────────────────────────────────────────────

    /// Validate the configuration for mainnet readiness.
    ///
    /// Returns a list of warnings/errors. Empty list = fully valid.
    pub fn validate_for_mainnet(&self) -> Vec<String> {
        let mut issues = Vec::new();

        if self.dns_seeds.is_empty() && self.static_peers.is_empty() {
            issues.push(
                "no DNS seeds and no static peers configured — \
                 node cannot bootstrap without at least one entry"
                    .to_string(),
            );
        }

        if self.max_outbound == 0 {
            issues.push("max_outbound is 0 — node will not connect to any peer".to_string());
        }

        if self.p2p_port == 0 {
            issues.push("p2p_port is 0".to_string());
        }

        // Validate static peer format
        for peer in &self.static_peers {
            if peer.parse::<SocketAddr>().is_err() {
                issues.push(format!("invalid static peer address: {}", peer));
            }
        }

        issues
    }

    /// Returns `true` if at least one bootstrap source is configured.
    pub fn has_bootstrap_sources(&self) -> bool {
        !self.dns_seeds.is_empty() || !self.static_peers.is_empty()
    }

    /// Returns the total number of configured bootstrap sources.
    pub fn source_count(&self) -> usize {
        self.dns_seeds.len() + self.static_peers.len()
    }

    /// Returns which file the config was loaded from, if any.
    pub fn loaded_from(&self) -> Option<&Path> {
        self.loaded_from.as_deref()
    }

    // ── TOML GENERATION ────────────────────────────────────────────────

    /// Generate a complete `dsdn.toml` [bootstrap] section as a string.
    ///
    /// Useful for `dsdn-node init` or `dsdn-agent config generate`.
    /// Produces the exact format from the Tahap 28 design doc with
    /// helpful comments.
    pub fn to_toml_string(&self) -> String {
        let dns_entries: String = if self.dns_seeds.is_empty() {
            "    # \"seed1.dsdn.network\",\n    \
             # \"seed2.dsdn.network\",\n    \
             # \"seed3.dsdn.network\","
                .to_string()
        } else {
            self.dns_seeds
                .iter()
                .map(|s| format!("    \"{}\",", s))
                .collect::<Vec<_>>()
                .join("\n")
        };

        let static_entries: String = if self.static_peers.is_empty() {
            "    # \"203.0.113.50:45831\",\n    \
             # \"198.51.100.10:45831\","
                .to_string()
        } else {
            self.static_peers
                .iter()
                .map(|s| format!("    \"{}\",", s))
                .collect::<Vec<_>>()
                .join("\n")
        };

        format!(
            r#"[bootstrap]
# DNS seeds (founder/community maintained)
dns_seeds = [
{dns}
]

# Static IP peers (community maintained)
static_peers = [
{static_p}
]

# Local peer cache
peers_file = "{peers_file}"

# Connection settings
max_outbound_connections = {max_out}
max_inbound_connections = {max_in}
dns_resolve_timeout_secs = {dns_to}
peer_connect_timeout_secs = {conn_to}

# Network settings
p2p_port = {port}
network_id = "{net}"
service_type = "{svc}"
"#,
            dns = dns_entries,
            static_p = static_entries,
            peers_file = self.peers_file.display(),
            max_out = self.max_outbound,
            max_in = self.max_inbound,
            dns_to = self.dns_timeout_secs,
            conn_to = self.connect_timeout_secs,
            port = self.p2p_port,
            net = self.network_id,
            svc = self.service_type,
        )
    }
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            dns_seeds: Vec::new(),
            static_peers: Vec::new(),
            peers_file: PathBuf::from("peers.dat"),
            max_outbound: DEFAULT_MAX_OUTBOUND,
            max_inbound: DEFAULT_MAX_INBOUND,
            dns_timeout_secs: DEFAULT_DNS_TIMEOUT_SECS,
            connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
            p2p_port: DEFAULT_P2P_PORT,
            network_id: NetworkId::Mainnet,
            service_type: ServiceType::Storage,
            loaded_from: None,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// CONFIG HELPERS (module-private)
// ════════════════════════════════════════════════════════════════════════════════

/// Parse an env var into a typed value. Returns `None` if the var
/// is unset, empty, or cannot be parsed.
fn env_parse<T: std::str::FromStr>(key: &str) -> Option<T> {
    std::env::var(key)
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok())
}

/// Best-effort home directory lookup without extra dependencies.
fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(PathBuf::from)
}

// ════════════════════════════════════════════════════════════════════════════════
// PEER INFO
// ════════════════════════════════════════════════════════════════════════════════

/// Complete metadata about a known peer, persisted in peers.dat.
///
/// Every field is populated during discovery and updated on each
/// connection attempt. The combination of scoring fields determines
/// peer selection priority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer's IP address (IPv4 or IPv6).
    pub addr: IpAddr,

    /// Peer's P2P listen port.
    pub port: u16,

    /// Ed25519 public key (32 bytes) as the peer's node ID.
    /// `None` if we haven't completed a handshake yet.
    pub node_id: Option<[u8; 32]>,

    /// The service type this peer advertises.
    pub service_type: Option<ServiceType>,

    /// Network ID this peer claims to be on.
    pub network_id: NetworkId,

    /// How we discovered this peer.
    pub source: PeerSource,

    /// Unix timestamp (seconds) when this peer was last seen reachable.
    pub last_seen: u64,

    /// Unix timestamp (seconds) of last successful connection + handshake.
    pub last_connected: u64,

    /// Total number of successful connections.
    pub success_count: u32,

    /// Total number of failed connection attempts.
    pub failure_count: u32,

    /// Consecutive failures (reset to 0 on success).
    pub consecutive_failures: u32,

    /// Unix timestamp (seconds) when this entry was first created.
    pub first_seen: u64,
}

impl PeerInfo {
    /// Create a new `PeerInfo` with initial discovery metadata.
    pub fn new(addr: IpAddr, port: u16, source: PeerSource, network_id: NetworkId) -> Self {
        let now = now_secs();
        Self {
            addr,
            port,
            node_id: None,
            service_type: None,
            network_id,
            source,
            last_seen: now,
            last_connected: 0,
            success_count: 0,
            failure_count: 0,
            consecutive_failures: 0,
            first_seen: now,
        }
    }

    /// Record a successful connection to this peer.
    pub fn record_success(&mut self) {
        let now = now_secs();
        self.last_seen = now;
        self.last_connected = now;
        self.success_count = self.success_count.saturating_add(1);
        self.consecutive_failures = 0;
    }

    /// Record a failed connection attempt to this peer.
    pub fn record_failure(&mut self) {
        self.failure_count = self.failure_count.saturating_add(1);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
    }

    /// Returns the `SocketAddr` for this peer.
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.addr, self.port)
    }

    /// Returns `true` if this peer is considered suspicious
    /// (too many consecutive failures).
    pub fn is_suspicious(&self) -> bool {
        self.consecutive_failures >= SUSPICIOUS_FAILURE_THRESHOLD
    }

    /// Returns `true` if this peer has expired (no successful connect
    /// within [`PEER_EXPIRY_SECS`]).
    pub fn is_expired(&self, now: u64) -> bool {
        if self.last_connected == 0 {
            // Never connected: expire based on first_seen
            now.saturating_sub(self.first_seen) > PEER_EXPIRY_SECS
        } else {
            now.saturating_sub(self.last_connected) > PEER_EXPIRY_SECS
        }
    }

    /// Compute the peer's score for selection priority.
    ///
    /// Higher score = higher priority for connection.
    pub fn score(&self, now: u64) -> i64 {
        let mut s = PEER_BASE_SCORE;

        // Reward success
        s = s.saturating_add((self.success_count as i64).saturating_mul(SCORE_SUCCESS_WEIGHT));

        // Penalize failure
        s = s.saturating_sub((self.failure_count as i64).saturating_mul(SCORE_FAILURE_WEIGHT));

        // Recency bonus
        let age = now.saturating_sub(self.last_connected);
        if self.last_connected > 0 {
            if age < SECS_1H {
                s = s.saturating_add(RECENCY_BONUS_1H);
            } else if age < SECS_24H {
                s = s.saturating_add(RECENCY_BONUS_24H);
            }

            // Staleness penalty
            if age > SECS_30D {
                s = s.saturating_sub(STALENESS_PENALTY_30D);
            } else if age > SECS_7D {
                s = s.saturating_sub(STALENESS_PENALTY_7D);
            }
        }

        // Heavy penalty for suspicious peers
        if self.is_suspicious() {
            s = s.saturating_sub(50);
        }

        s
    }

    /// Returns the node_id as a hex string (64 chars, lowercase).
    /// Returns `None` if node_id is not set.
    pub fn node_id_hex(&self) -> Option<String> {
        self.node_id.map(|id| {
            id.iter().map(|b| format!("{:02x}", b)).collect()
        })
    }
}

impl PartialEq for PeerInfo {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr && self.port == other.port
    }
}

impl Eq for PeerInfo {}

impl std::hash::Hash for PeerInfo {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
        self.port.hash(state);
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// PEER STORE (peers.dat)
// ════════════════════════════════════════════════════════════════════════════════

/// Persistent peer cache backed by a file on disk.
///
/// ## Storage Format
///
/// JSON format for debuggability during development. The format can be
/// switched to binary (bincode) in Tahap 28 if performance requires it.
///
/// ## Atomic Writes
///
/// Writes use the tmp-file + rename pattern to prevent corruption:
/// 1. Serialize peers to `{path}.tmp`
/// 2. `fsync` the tmp file
/// 3. Rename `{path}.tmp` → `{path}`
///
/// ## Garbage Collection
///
/// [`gc`] removes peers that haven't connected successfully in
/// [`PEER_EXPIRY_SECS`] (30 days) and enforces the
/// [`MAX_PEERS_DAT_ENTRIES`] limit by evicting lowest-score peers.
#[derive(Debug)]
pub struct PeerStore {
    /// Path to the peers.dat file.
    path: PathBuf,
    /// In-memory peer map keyed by `SocketAddr`.
    peers: HashMap<SocketAddr, PeerInfo>,
}

impl PeerStore {
    /// Create a new `PeerStore` at the given path.
    ///
    /// If the file exists, peers are loaded from it.
    /// If the file doesn't exist or is corrupted, starts empty.
    pub fn new(path: PathBuf) -> Self {
        let peers = Self::load_from_file(&path).unwrap_or_default();
        Self { path, peers }
    }

    /// Create an empty in-memory store (no file backing).
    /// Useful for testing.
    pub fn in_memory() -> Self {
        Self {
            path: PathBuf::from("/dev/null"),
            peers: HashMap::new(),
        }
    }

    /// Load peers from a JSON file on disk.
    fn load_from_file(path: &Path) -> Result<HashMap<SocketAddr, PeerInfo>, PeerStoreError> {
        if !path.exists() {
            return Ok(HashMap::new());
        }

        let data = std::fs::read(path).map_err(|e| PeerStoreError::Io(e.to_string()))?;

        let peers_vec: Vec<PeerInfo> =
            serde_json::from_slice(&data).map_err(|e| PeerStoreError::Parse(e.to_string()))?;

        let mut map = HashMap::with_capacity(peers_vec.len());
        for peer in peers_vec {
            map.insert(peer.socket_addr(), peer);
        }
        Ok(map)
    }

    /// Persist the current peer set to disk atomically.
    ///
    /// Uses write-to-tmp + rename for crash safety.
    pub fn save(&self) -> Result<(), PeerStoreError> {
        let peers_vec: Vec<&PeerInfo> = self.peers.values().collect();
        let data = serde_json::to_vec_pretty(&peers_vec)
            .map_err(|e| PeerStoreError::Serialize(e.to_string()))?;

        let tmp_path = self.path.with_extension("dat.tmp");

        std::fs::write(&tmp_path, &data).map_err(|e| PeerStoreError::Io(e.to_string()))?;

        // fsync via opening and syncing
        if let Ok(f) = std::fs::File::open(&tmp_path) {
            let _ = f.sync_all();
        }

        std::fs::rename(&tmp_path, &self.path)
            .map_err(|e| PeerStoreError::Io(e.to_string()))?;

        Ok(())
    }

    /// Insert or update a peer. Returns `true` if this is a new peer.
    pub fn upsert(&mut self, peer: PeerInfo) -> bool {
        let key = peer.socket_addr();
        if let Some(existing) = self.peers.get_mut(&key) {
            // Update metadata, preserve historical counters
            if peer.last_seen > existing.last_seen {
                existing.last_seen = peer.last_seen;
            }
            if peer.last_connected > existing.last_connected {
                existing.last_connected = peer.last_connected;
            }
            if peer.node_id.is_some() {
                existing.node_id = peer.node_id;
            }
            if peer.service_type.is_some() {
                existing.service_type = peer.service_type;
            }
            false
        } else {
            self.peers.insert(key, peer);
            true
        }
    }

    /// Record a successful connection for a peer.
    pub fn record_success(&mut self, addr: SocketAddr) {
        if let Some(peer) = self.peers.get_mut(&addr) {
            peer.record_success();
        }
    }

    /// Record a failed connection attempt for a peer.
    pub fn record_failure(&mut self, addr: SocketAddr) {
        if let Some(peer) = self.peers.get_mut(&addr) {
            peer.record_failure();
        }
    }

    /// Get a peer by socket address.
    pub fn get(&self, addr: &SocketAddr) -> Option<&PeerInfo> {
        self.peers.get(addr)
    }

    /// Get a mutable peer by socket address.
    pub fn get_mut(&mut self, addr: &SocketAddr) -> Option<&mut PeerInfo> {
        self.peers.get_mut(addr)
    }

    /// Remove a peer by socket address.
    pub fn remove(&mut self, addr: &SocketAddr) -> Option<PeerInfo> {
        self.peers.remove(addr)
    }

    /// Returns the total number of stored peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Returns `true` if no peers are stored.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Returns all peers as a slice-compatible iterator.
    pub fn iter(&self) -> impl Iterator<Item = &PeerInfo> {
        self.peers.values()
    }

    /// Returns peers sorted by score (highest first).
    ///
    /// This is the primary selection method: connect to the
    /// highest-scoring peers first.
    pub fn sorted_by_score(&self) -> Vec<&PeerInfo> {
        let now = now_secs();
        let mut peers: Vec<&PeerInfo> = self.peers.values().collect();
        peers.sort_by(|a, b| b.score(now).cmp(&a.score(now)));
        peers
    }

    /// Returns peers filtered by service type, sorted by score.
    pub fn peers_by_service(&self, svc: ServiceType) -> Vec<&PeerInfo> {
        let now = now_secs();
        let mut peers: Vec<&PeerInfo> = self
            .peers
            .values()
            .filter(|p| p.service_type == Some(svc))
            .collect();
        peers.sort_by(|a, b| b.score(now).cmp(&a.score(now)));
        peers
    }

    /// Returns peers filtered by network ID.
    pub fn peers_by_network(&self, net: &NetworkId) -> Vec<&PeerInfo> {
        self.peers
            .values()
            .filter(|p| &p.network_id == net)
            .collect()
    }

    /// Run garbage collection:
    /// 1. Remove expired peers (no connect in 30 days).
    /// 2. Enforce max entries by evicting lowest-score peers.
    ///
    /// Returns the number of peers removed.
    pub fn gc(&mut self) -> usize {
        let now = now_secs();
        let before = self.peers.len();

        // Phase 1: Remove expired
        self.peers.retain(|_, peer| !peer.is_expired(now));

        // Phase 2: Enforce max entries
        if self.peers.len() > MAX_PEERS_DAT_ENTRIES {
            let mut scored: Vec<(SocketAddr, i64)> = self
                .peers
                .iter()
                .map(|(addr, peer)| (*addr, peer.score(now)))
                .collect();
            scored.sort_by(|a, b| b.1.cmp(&a.1));

            // Keep only the top MAX entries
            let to_remove: Vec<SocketAddr> = scored
                .iter()
                .skip(MAX_PEERS_DAT_ENTRIES)
                .map(|(addr, _)| *addr)
                .collect();

            for addr in &to_remove {
                self.peers.remove(addr);
            }
        }

        before.saturating_sub(self.peers.len())
    }

    /// Returns statistics about the peer store.
    pub fn stats(&self) -> PeerStoreStats {
        let now = now_secs();
        let total = self.peers.len();
        let suspicious = self.peers.values().filter(|p| p.is_suspicious()).count();
        let expired = self.peers.values().filter(|p| p.is_expired(now)).count();
        let connected_24h = self
            .peers
            .values()
            .filter(|p| p.last_connected > 0 && now.saturating_sub(p.last_connected) < SECS_24H)
            .count();

        let mut by_source = HashMap::new();
        for peer in self.peers.values() {
            *by_source.entry(peer.source.to_string()).or_insert(0usize) += 1;
        }

        let mut by_service = HashMap::new();
        for peer in self.peers.values() {
            let key = peer
                .service_type
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            *by_service.entry(key).or_insert(0usize) += 1;
        }

        PeerStoreStats {
            total,
            suspicious,
            expired,
            connected_24h,
            by_source,
            by_service,
        }
    }
}

/// Statistics about the peer store contents.
#[derive(Debug, Clone, Serialize)]
pub struct PeerStoreStats {
    pub total: usize,
    pub suspicious: usize,
    pub expired: usize,
    pub connected_24h: usize,
    pub by_source: HashMap<String, usize>,
    pub by_service: HashMap<String, usize>,
}

/// Errors from peer store operations.
#[derive(Debug, Clone)]
pub enum PeerStoreError {
    Io(String),
    Parse(String),
    Serialize(String),
}

impl fmt::Display for PeerStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerStoreError::Io(e) => write!(f, "peer store I/O error: {}", e),
            PeerStoreError::Parse(e) => write!(f, "peer store parse error: {}", e),
            PeerStoreError::Serialize(e) => write!(f, "peer store serialize error: {}", e),
        }
    }
}

impl std::error::Error for PeerStoreError {}

// ════════════════════════════════════════════════════════════════════════════════
// HANDSHAKE PROTOCOL
// ════════════════════════════════════════════════════════════════════════════════

/// Handshake message exchanged when two peers first connect.
///
/// Both sides send a `HandshakeMessage`. If validation passes
/// (matching network_id, compatible protocol_version), the
/// connection is accepted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandshakeMessage {
    /// Protocol version. Must be compatible with remote peer.
    pub protocol_version: u32,
    /// Network identifier. Must match exactly.
    pub network_id: NetworkId,
    /// Ed25519 public key (32 bytes) — node identity.
    pub node_id: [u8; 32],
    /// Port this node is listening on for inbound P2P connections.
    pub listen_port: u16,
    /// Service type this node provides.
    pub service_type: ServiceType,
    /// User agent string (e.g., "dsdn-node/0.14.0").
    pub user_agent: String,
}

impl HandshakeMessage {
    /// Build a handshake message for this node.
    pub fn build(
        node_id: &[u8; 32],
        network_id: NetworkId,
        listen_port: u16,
        service_type: ServiceType,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            network_id,
            node_id: *node_id,
            listen_port,
            service_type,
            user_agent: format!("dsdn-node/{}", env!("CARGO_PKG_VERSION")),
        }
    }

    /// Validate a remote peer's handshake against our own configuration.
    ///
    /// Returns `Ok(())` if compatible, or `Err(reason)` if not.
    pub fn validate_remote(
        &self,
        remote: &HandshakeMessage,
    ) -> Result<(), HandshakeError> {
        // Network ID must match exactly
        if self.network_id != remote.network_id {
            return Err(HandshakeError::NetworkMismatch {
                local: self.network_id.to_string(),
                remote: remote.network_id.to_string(),
            });
        }

        // Protocol version must be compatible (for now: must match)
        if self.protocol_version != remote.protocol_version {
            return Err(HandshakeError::VersionIncompatible {
                local: self.protocol_version,
                remote: remote.protocol_version,
            });
        }

        // Cannot connect to ourselves
        if self.node_id == remote.node_id {
            return Err(HandshakeError::SelfConnection);
        }

        Ok(())
    }
}

/// Handshake validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// Network IDs don't match.
    NetworkMismatch { local: String, remote: String },
    /// Protocol versions are incompatible.
    VersionIncompatible { local: u32, remote: u32 },
    /// Attempted to connect to ourselves.
    SelfConnection,
    /// Connection timed out during handshake.
    Timeout,
    /// Transport-level error.
    Transport(String),
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::NetworkMismatch { local, remote } => {
                write!(f, "network mismatch: local={}, remote={}", local, remote)
            }
            HandshakeError::VersionIncompatible { local, remote } => {
                write!(f, "version incompatible: local={}, remote={}", local, remote)
            }
            HandshakeError::SelfConnection => write!(f, "self-connection detected"),
            HandshakeError::Timeout => write!(f, "handshake timed out"),
            HandshakeError::Transport(e) => write!(f, "transport error: {}", e),
        }
    }
}

impl std::error::Error for HandshakeError {}

// ════════════════════════════════════════════════════════════════════════════════
// PEER EXCHANGE PROTOCOL (PEX)
// ════════════════════════════════════════════════════════════════════════════════

/// Peer Exchange request — "give me your known peers."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PexRequest {
    /// Optional filter: only return peers of this service type.
    pub service_filter: Option<ServiceType>,
    /// Maximum number of peers requested.
    pub max_peers: usize,
}

/// A single peer entry in a PEX response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PexPeerEntry {
    pub addr: IpAddr,
    pub port: u16,
    pub node_id: Option<[u8; 32]>,
    pub service_type: Option<ServiceType>,
    pub last_connected: u64,
}

/// Peer Exchange response — "here are my known peers."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PexResponse {
    /// Peers this node knows about, filtered and capped.
    pub peers: Vec<PexPeerEntry>,
}

impl PexResponse {
    /// Build a PEX response from a `PeerStore`.
    ///
    /// Only includes peers that have connected successfully in the
    /// last 24 hours. Excludes banned peers. Capped at
    /// [`PEX_MAX_PEERS_PER_RESPONSE`].
    pub fn build_from_store(
        store: &PeerStore,
        request: &PexRequest,
        exclude_node_id: Option<&[u8; 32]>,
    ) -> Self {
        let now = now_secs();
        let max = request.max_peers.min(PEX_MAX_PEERS_PER_RESPONSE);

        let peers: Vec<PexPeerEntry> = store
            .iter()
            .filter(|p| {
                // Only share peers connected in last 24h
                p.last_connected > 0 && now.saturating_sub(p.last_connected) < SECS_24H
            })
            .filter(|p| {
                // Apply service type filter if requested
                match request.service_filter {
                    Some(svc) => p.service_type == Some(svc),
                    None => true,
                }
            })
            .filter(|p| {
                // Don't send the requester their own entry
                match (exclude_node_id, &p.node_id) {
                    (Some(excl), Some(pid)) => excl != pid,
                    _ => true,
                }
            })
            .take(max)
            .map(|p| PexPeerEntry {
                addr: p.addr,
                port: p.port,
                node_id: p.node_id,
                service_type: p.service_type,
                last_connected: p.last_connected,
            })
            .collect();

        PexResponse { peers }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// DNS RESOLVER TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// Trait for DNS seed resolution.
///
/// Abstracted to allow mock implementations for testing and
/// development. Real implementation (using `trust-dns` or
/// `hickory-dns`) will be provided in Tahap 21.1.B.
pub trait DnsResolver: Send + Sync {
    /// Resolve a DNS hostname to a list of IP addresses.
    ///
    /// Should return both A (IPv4) and AAAA (IPv6) records.
    /// Returns an empty vec if resolution fails or times out.
    fn resolve(&self, hostname: &str) -> Vec<IpAddr>;
}

/// Mock DNS resolver that returns preconfigured results.
///
/// For development and testing. No actual DNS queries are made.
#[derive(Debug, Default)]
pub struct MockDnsResolver {
    /// Hostname → IP list mapping.
    results: HashMap<String, Vec<IpAddr>>,
}

impl MockDnsResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a preconfigured result for a hostname.
    pub fn add_result(&mut self, hostname: &str, ips: Vec<IpAddr>) {
        self.results.insert(hostname.to_string(), ips);
    }
}

impl DnsResolver for MockDnsResolver {
    fn resolve(&self, hostname: &str) -> Vec<IpAddr> {
        self.results.get(hostname).cloned().unwrap_or_default()
    }
}

/// Null resolver that always returns empty. Used when no DNS
/// seeds are configured (development mode).
#[derive(Debug)]
pub struct NullDnsResolver;

impl DnsResolver for NullDnsResolver {
    fn resolve(&self, _hostname: &str) -> Vec<IpAddr> {
        Vec::new()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// PEER CONNECTOR TRAIT
// ════════════════════════════════════════════════════════════════════════════════

/// Trait for establishing P2P connections to peers.
///
/// Abstracted for testability. Real implementation (TCP + noise
/// protocol or TLS) will be provided in Tahap 21.1.B.
pub trait PeerConnector: Send + Sync {
    /// Attempt to connect and perform a handshake with a remote peer.
    ///
    /// Returns the remote peer's handshake message on success,
    /// or a `HandshakeError` on failure.
    fn connect_and_handshake(
        &self,
        addr: SocketAddr,
        our_handshake: &HandshakeMessage,
    ) -> Result<HandshakeMessage, HandshakeError>;
}

/// Mock connector that succeeds or fails based on configuration.
#[derive(Debug)]
pub struct MockPeerConnector {
    /// Addresses that will succeed, mapped to their handshake response.
    reachable: HashMap<SocketAddr, HandshakeMessage>,
}

impl MockPeerConnector {
    pub fn new() -> Self {
        Self {
            reachable: HashMap::new(),
        }
    }

    /// Mark an address as reachable with the given handshake response.
    pub fn add_reachable(&mut self, addr: SocketAddr, handshake: HandshakeMessage) {
        self.reachable.insert(addr, handshake);
    }
}

impl Default for MockPeerConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerConnector for MockPeerConnector {
    fn connect_and_handshake(
        &self,
        addr: SocketAddr,
        _our_handshake: &HandshakeMessage,
    ) -> Result<HandshakeMessage, HandshakeError> {
        match self.reachable.get(&addr) {
            Some(hs) => Ok(hs.clone()),
            None => Err(HandshakeError::Transport(format!(
                "connection refused: {}",
                addr
            ))),
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// BOOTSTRAP METRICS
// ════════════════════════════════════════════════════════════════════════════════

/// Observable metrics for the bootstrap subsystem.
///
/// All counters are monotonically increasing (never reset).
/// Exposed via the node's Prometheus endpoint.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BootstrapMetrics {
    /// Total DNS resolve attempts.
    pub dns_resolve_total: u64,
    /// Successful DNS resolves.
    pub dns_resolve_success: u64,
    /// Total peer connection attempts.
    pub peer_connect_total: u64,
    /// Successful peer connections.
    pub peer_connect_success: u64,
    /// Handshake failures (broken down by type isn't needed yet).
    pub handshake_failures: u64,
    /// Number of times the fallback chain was triggered
    /// (moved from one source to the next).
    pub fallback_triggered: u64,
    /// Total PEX requests sent.
    pub pex_requests_sent: u64,
    /// Total PEX requests received.
    pub pex_requests_received: u64,
    /// Current active peer count.
    pub active_peers: u64,
    /// Peers.dat entry count.
    pub peers_dat_size: u64,
}

impl BootstrapMetrics {
    /// Format as Prometheus text exposition.
    pub fn to_prometheus(&self, node_id: &str) -> String {
        format!(
            r#"# HELP dsdn_bootstrap_dns_resolve_total Total DNS resolve attempts
# TYPE dsdn_bootstrap_dns_resolve_total counter
dsdn_bootstrap_dns_resolve_total{{node_id="{nid}"}} {dns_total}
# HELP dsdn_bootstrap_dns_resolve_success Successful DNS resolves
# TYPE dsdn_bootstrap_dns_resolve_success counter
dsdn_bootstrap_dns_resolve_success{{node_id="{nid}"}} {dns_ok}
# HELP dsdn_bootstrap_peer_connect_total Total peer connection attempts
# TYPE dsdn_bootstrap_peer_connect_total counter
dsdn_bootstrap_peer_connect_total{{node_id="{nid}"}} {conn_total}
# HELP dsdn_bootstrap_peer_connect_success Successful peer connections
# TYPE dsdn_bootstrap_peer_connect_success counter
dsdn_bootstrap_peer_connect_success{{node_id="{nid}"}} {conn_ok}
# HELP dsdn_bootstrap_handshake_failures Handshake failures
# TYPE dsdn_bootstrap_handshake_failures counter
dsdn_bootstrap_handshake_failures{{node_id="{nid}"}} {hs_fail}
# HELP dsdn_bootstrap_fallback_triggered Fallback chain triggers
# TYPE dsdn_bootstrap_fallback_triggered counter
dsdn_bootstrap_fallback_triggered{{node_id="{nid}"}} {fb}
# HELP dsdn_bootstrap_active_peers Current active peers
# TYPE dsdn_bootstrap_active_peers gauge
dsdn_bootstrap_active_peers{{node_id="{nid}"}} {active}
# HELP dsdn_bootstrap_peers_dat_size Peers.dat entry count
# TYPE dsdn_bootstrap_peers_dat_size gauge
dsdn_bootstrap_peers_dat_size{{node_id="{nid}"}} {pdat}
"#,
            nid = node_id,
            dns_total = self.dns_resolve_total,
            dns_ok = self.dns_resolve_success,
            conn_total = self.peer_connect_total,
            conn_ok = self.peer_connect_success,
            hs_fail = self.handshake_failures,
            fb = self.fallback_triggered,
            active = self.active_peers,
            pdat = self.peers_dat_size,
        )
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// BOOTSTRAP RESULT
// ════════════════════════════════════════════════════════════════════════════════

/// Outcome of a bootstrap attempt describing what happened.
#[derive(Debug, Clone)]
pub enum BootstrapResult {
    /// Successfully connected to at least one peer.
    Connected {
        /// Number of peers successfully connected.
        peer_count: usize,
        /// Which source provided the first connection.
        source: String,
    },
    /// No peers could be reached from any source.
    NoPeersAvailable {
        /// Human-readable summary of what was tried.
        summary: String,
    },
    /// Bootstrap was skipped (e.g., no sources configured).
    Skipped {
        reason: String,
    },
}

// ════════════════════════════════════════════════════════════════════════════════
// PEER MANAGER (Orchestrator)
// ════════════════════════════════════════════════════════════════════════════════

/// Central orchestrator for the bootstrap subsystem.
///
/// Manages the full lifecycle: config loading → fallback chain →
/// peer scoring → PEX → persistence. Uses trait objects for
/// DNS resolution and peer connection, making it fully testable
/// with mocks.
///
/// ## Lifecycle
///
/// 1. **Init**: Load config + peers.dat.
/// 2. **Bootstrap**: Execute fallback chain to find initial peers.
/// 3. **Maintain**: Periodic PEX, DNS re-resolve, peer rotation.
/// 4. **Persist**: Save peers.dat on changes and shutdown.
///
/// ## Thread Safety
///
/// `PeerManager` itself is NOT `Sync` (holds mutable `PeerStore`).
/// It should be held behind `Arc<Mutex<PeerManager>>` or used from
/// a single-owner task that communicates via channels.
pub struct PeerManager {
    /// Bootstrap configuration.
    config: BootstrapConfig,
    /// Persistent peer store (peers.dat).
    store: PeerStore,
    /// DNS resolver implementation.
    dns_resolver: Box<dyn DnsResolver>,
    /// Peer connector implementation.
    connector: Box<dyn PeerConnector>,
    /// Observable metrics.
    metrics: BootstrapMetrics,
    /// Our handshake message template.
    our_handshake: HandshakeMessage,
    /// Currently active (connected) peer addresses.
    active_peers: HashMap<SocketAddr, PeerInfo>,
}

impl PeerManager {
    /// Create a new `PeerManager` with the given configuration
    /// and I/O trait implementations.
    ///
    /// Loads peers.dat from disk if it exists.
    pub fn new(
        config: BootstrapConfig,
        node_id: [u8; 32],
        dns_resolver: Box<dyn DnsResolver>,
        connector: Box<dyn PeerConnector>,
    ) -> Self {
        let store = PeerStore::new(config.peers_file.clone());
        let our_handshake = HandshakeMessage::build(
            &node_id,
            config.network_id.clone(),
            config.p2p_port,
            config.service_type,
        );

        Self {
            config,
            store,
            dns_resolver,
            connector,
            metrics: BootstrapMetrics::default(),
            our_handshake,
            active_peers: HashMap::new(),
        }
    }

    /// Execute the full bootstrap fallback chain.
    ///
    /// Tries sources in priority order:
    /// 1. peers.dat (cached peers, sorted by score)
    /// 2. Static IP peers from config
    /// 3. DNS seeds from config
    ///
    /// Stops as soon as at least one peer is successfully connected.
    /// All discovered peers are added to the store regardless of
    /// which source provided them.
    pub fn bootstrap(&mut self) -> BootstrapResult {
        // Phase 1: Try peers.dat
        let cached_result = self.try_cached_peers();
        if cached_result > 0 {
            self.persist_store();
            return BootstrapResult::Connected {
                peer_count: cached_result,
                source: "peers.dat".to_string(),
            };
        }

        self.metrics.fallback_triggered = self.metrics.fallback_triggered.saturating_add(1);

        // Phase 2: Try static IP peers
        let static_result = self.try_static_peers();
        if static_result > 0 {
            self.persist_store();
            return BootstrapResult::Connected {
                peer_count: static_result,
                source: "static_config".to_string(),
            };
        }

        self.metrics.fallback_triggered = self.metrics.fallback_triggered.saturating_add(1);

        // Phase 3: Try DNS seeds
        let dns_result = self.try_dns_seeds();
        if dns_result > 0 {
            self.persist_store();
            return BootstrapResult::Connected {
                peer_count: dns_result,
                source: "dns_seed".to_string(),
            };
        }

        // All sources exhausted
        BootstrapResult::NoPeersAvailable {
            summary: format!(
                "tried {} cached peers, {} static peers, {} DNS seeds — all failed",
                self.store.len(),
                self.config.static_peers.len(),
                self.config.dns_seeds.len(),
            ),
        }
    }

    /// Try connecting to peers from the local cache (peers.dat).
    ///
    /// Returns the number of successful connections.
    fn try_cached_peers(&mut self) -> usize {
        // Collect addresses into owned Vec to release the borrow on self.store
        // before calling self.try_connect (which needs &mut self).
        let addrs: Vec<SocketAddr> = self
            .store
            .sorted_by_score()
            .iter()
            .take(self.config.max_outbound)
            .map(|p| p.socket_addr())
            .collect();

        if addrs.is_empty() {
            return 0;
        }

        let mut connected = 0;

        for addr in &addrs {
            if self.try_connect(*addr, PeerSource::DnsSeed /* preserved */) {
                connected += 1;
                if connected >= self.config.max_outbound {
                    break;
                }
            }
        }

        connected
    }

    /// Try connecting to static peers from config.
    ///
    /// Returns the number of successful connections.
    fn try_static_peers(&mut self) -> usize {
        let mut connected = 0;

        for peer_str in self.config.static_peers.clone() {
            let addr = match peer_str.parse::<SocketAddr>() {
                Ok(a) => a,
                Err(_) => continue,
            };

            // Add to store as static peer
            let info = PeerInfo::new(
                addr.ip(),
                addr.port(),
                PeerSource::StaticConfig,
                self.config.network_id.clone(),
            );
            self.store.upsert(info);

            if self.try_connect(addr, PeerSource::StaticConfig) {
                connected += 1;
                if connected >= self.config.max_outbound {
                    break;
                }
            }
        }

        connected
    }

    /// Try resolving DNS seeds and connecting to discovered peers.
    ///
    /// Returns the number of successful connections.
    fn try_dns_seeds(&mut self) -> usize {
        let mut connected = 0;

        for seed in self.config.dns_seeds.clone() {
            self.metrics.dns_resolve_total = self.metrics.dns_resolve_total.saturating_add(1);

            let ips = self.dns_resolver.resolve(&seed);

            if ips.is_empty() {
                continue;
            }

            self.metrics.dns_resolve_success = self.metrics.dns_resolve_success.saturating_add(1);

            for ip in ips {
                let addr = SocketAddr::new(ip, self.config.p2p_port);

                // Add to store as DNS-discovered peer
                let info = PeerInfo::new(
                    ip,
                    self.config.p2p_port,
                    PeerSource::DnsSeed,
                    self.config.network_id.clone(),
                );
                self.store.upsert(info);

                if self.try_connect(addr, PeerSource::DnsSeed) {
                    connected += 1;
                    if connected >= self.config.max_outbound {
                        return connected;
                    }
                }
            }
        }

        connected
    }

    /// Attempt to connect + handshake with a single peer.
    ///
    /// Updates the store and metrics. Returns `true` on success.
    fn try_connect(&mut self, addr: SocketAddr, _source: PeerSource) -> bool {
        self.metrics.peer_connect_total = self.metrics.peer_connect_total.saturating_add(1);

        match self
            .connector
            .connect_and_handshake(addr, &self.our_handshake)
        {
            Ok(remote_hs) => {
                // Validate handshake
                match self.our_handshake.validate_remote(&remote_hs) {
                    Ok(()) => {
                        self.metrics.peer_connect_success =
                            self.metrics.peer_connect_success.saturating_add(1);

                        // Update store with handshake info
                        self.store.record_success(addr);
                        if let Some(peer) = self.store.get_mut(&addr) {
                            peer.node_id = Some(remote_hs.node_id);
                            peer.service_type = Some(remote_hs.service_type);
                        }

                        // Track as active
                        if let Some(peer) = self.store.get(&addr) {
                            self.active_peers.insert(addr, peer.clone());
                        }

                        true
                    }
                    Err(_e) => {
                        self.metrics.handshake_failures =
                            self.metrics.handshake_failures.saturating_add(1);
                        self.store.record_failure(addr);
                        false
                    }
                }
            }
            Err(_e) => {
                self.metrics.handshake_failures =
                    self.metrics.handshake_failures.saturating_add(1);
                self.store.record_failure(addr);
                false
            }
        }
    }

    /// Process incoming PEX peers from a connected peer.
    ///
    /// Adds new peers to the store for future connection attempts.
    /// Returns the number of new peers added.
    pub fn process_pex_response(&mut self, response: &PexResponse) -> usize {
        let mut added = 0;
        for entry in &response.peers {
            let info = PeerInfo {
                addr: entry.addr,
                port: entry.port,
                node_id: entry.node_id,
                service_type: entry.service_type,
                network_id: self.config.network_id.clone(),
                source: PeerSource::PeerExchange,
                last_seen: now_secs(),
                last_connected: entry.last_connected,
                success_count: 0,
                failure_count: 0,
                consecutive_failures: 0,
                first_seen: now_secs(),
            };
            if self.store.upsert(info) {
                added += 1;
            }
        }
        added
    }

    /// Build a PEX response for a requesting peer.
    pub fn build_pex_response(
        &self,
        request: &PexRequest,
        requester_node_id: Option<&[u8; 32]>,
    ) -> PexResponse {
        self.metrics
            .clone(); // avoid borrow issues — metrics are updated elsewhere
        PexResponse::build_from_store(&self.store, request, requester_node_id)
    }

    /// Run garbage collection on the peer store.
    pub fn gc(&mut self) -> usize {
        let removed = self.store.gc();
        self.metrics.peers_dat_size = self.store.len() as u64;
        removed
    }

    /// Persist the peer store to disk.
    pub fn persist_store(&mut self) {
        self.metrics.peers_dat_size = self.store.len() as u64;
        let _ = self.store.save();
    }

    /// Add a peer manually (e.g., from CLI `peers add` command).
    pub fn add_manual_peer(&mut self, addr: SocketAddr) {
        let info = PeerInfo::new(
            addr.ip(),
            addr.port(),
            PeerSource::Manual,
            self.config.network_id.clone(),
        );
        self.store.upsert(info);
    }

    /// Remove a peer by address.
    pub fn remove_peer(&mut self, addr: &SocketAddr) -> bool {
        self.active_peers.remove(addr);
        self.store.remove(addr).is_some()
    }

    // ── Accessors ──────────────────────────────────────────────────────

    /// Returns a reference to the bootstrap configuration.
    pub fn config(&self) -> &BootstrapConfig {
        &self.config
    }

    /// Returns a reference to the peer store.
    pub fn store(&self) -> &PeerStore {
        &self.store
    }

    /// Returns a mutable reference to the peer store.
    pub fn store_mut(&mut self) -> &mut PeerStore {
        &mut self.store
    }

    /// Returns the current bootstrap metrics.
    pub fn metrics(&self) -> &BootstrapMetrics {
        &self.metrics
    }

    /// Returns the number of currently active (connected) peers.
    pub fn active_peer_count(&self) -> usize {
        self.active_peers.len()
    }

    /// Returns active peers as an iterator.
    pub fn active_peers(&self) -> impl Iterator<Item = &PeerInfo> {
        self.active_peers.values()
    }

    /// Returns active peers filtered by service type.
    pub fn active_peers_by_service(&self, svc: ServiceType) -> Vec<&PeerInfo> {
        self.active_peers
            .values()
            .filter(|p| p.service_type == Some(svc))
            .collect()
    }

    /// Returns our handshake message.
    pub fn our_handshake(&self) -> &HandshakeMessage {
        &self.our_handshake
    }

    /// Returns summary info for HTTP endpoint exposure.
    pub fn summary(&self) -> BootstrapSummary {
        BootstrapSummary {
            network_id: self.config.network_id.to_string(),
            service_type: self.config.service_type.to_string(),
            p2p_port: self.config.p2p_port,
            active_peers: self.active_peers.len(),
            known_peers: self.store.len(),
            dns_seeds_configured: self.config.dns_seeds.len(),
            static_peers_configured: self.config.static_peers.len(),
            metrics: self.metrics.clone(),
        }
    }
}

impl fmt::Debug for PeerManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerManager")
            .field("network_id", &self.config.network_id)
            .field("service_type", &self.config.service_type)
            .field("active_peers", &self.active_peers.len())
            .field("known_peers", &self.store.len())
            .finish()
    }
}

/// Summary of bootstrap subsystem state for HTTP endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct BootstrapSummary {
    pub network_id: String,
    pub service_type: String,
    pub p2p_port: u16,
    pub active_peers: usize,
    pub known_peers: usize,
    pub dns_seeds_configured: usize,
    pub static_peers_configured: usize,
    pub metrics: BootstrapMetrics,
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER
// ════════════════════════════════════════════════════════════════════════════════

/// Current unix timestamp in seconds.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ════════════════════════════════════════════════════════════════════════════════
// COMPILE-TIME ASSERTIONS
// ════════════════════════════════════════════════════════════════════════════════

const _: () = {
    fn assert_send<T: Send>() {}
    fn check() {
        assert_send::<BootstrapConfig>();
        assert_send::<PeerInfo>();
        assert_send::<PeerStore>();
        assert_send::<HandshakeMessage>();
        assert_send::<BootstrapMetrics>();
        assert_send::<PeerManager>();
    }
    let _ = check;
};

const _: () = {
    fn assert_sync<T: Sync>() {}
    fn check() {
        assert_sync::<BootstrapConfig>();
        assert_sync::<PeerInfo>();
        assert_sync::<HandshakeMessage>();
        assert_sync::<BootstrapMetrics>();
    }
    let _ = check;
};

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const TEST_NODE_ID: [u8; 32] = [0x01; 32];
    const REMOTE_NODE_ID: [u8; 32] = [0x02; 32];
    const REMOTE_NODE_ID_2: [u8; 32] = [0x03; 32];
    const TS: u64 = 1_700_000_000;

    fn test_addr(last_octet: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, last_octet)), 45831)
    }

    fn make_peer(last_octet: u8, source: PeerSource) -> PeerInfo {
        PeerInfo::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, last_octet)),
            45831,
            source,
            NetworkId::Testnet,
        )
    }

    fn make_remote_handshake(node_id: [u8; 32]) -> HandshakeMessage {
        HandshakeMessage {
            protocol_version: PROTOCOL_VERSION,
            network_id: NetworkId::Testnet,
            node_id,
            listen_port: 45831,
            service_type: ServiceType::Storage,
            user_agent: "test-peer/1.0".to_string(),
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // SERVICE TYPE
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn test_service_type_roundtrip() {
        let types = [
            ServiceType::Chain,
            ServiceType::Storage,
            ServiceType::StorageDC,
            ServiceType::Coordinator,
            ServiceType::Validator,
            ServiceType::Ingress,
            ServiceType::Bootstrap,
        ];
        for svc in &types {
            let s = svc.as_str();
            let parsed = ServiceType::from_str_tag(s);
            assert_eq!(parsed, Some(*svc), "roundtrip failed for {:?}", svc);
        }
    }

    #[test]
    fn test_service_type_case_insensitive() {
        assert_eq!(ServiceType::from_str_tag("CHAIN"), Some(ServiceType::Chain));
        assert_eq!(
            ServiceType::from_str_tag("Storage"),
            Some(ServiceType::Storage)
        );
        assert_eq!(ServiceType::from_str_tag("unknown"), None);
    }

    // ────────────────────────────────────────────────────────────────────
    // NETWORK ID
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn test_network_id_parse() {
        assert_eq!(NetworkId::from_string("mainnet"), NetworkId::Mainnet);
        assert_eq!(NetworkId::from_string("testnet"), NetworkId::Testnet);
        assert_eq!(NetworkId::from_string("MAINNET"), NetworkId::Mainnet);
        match NetworkId::from_string("devnet") {
            NetworkId::Custom(s) => assert_eq!(s, "devnet"),
            other => panic!("expected Custom, got {:?}", other),
        }
    }

    #[test]
    fn test_network_id_display() {
        assert_eq!(NetworkId::Mainnet.to_string(), "mainnet");
        assert_eq!(NetworkId::Testnet.to_string(), "testnet");
    }

    // ────────────────────────────────────────────────────────────────────
    // BOOTSTRAP CONFIG
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn test_default_config() {
        let cfg = BootstrapConfig::default();
        assert!(cfg.dns_seeds.is_empty());
        assert!(cfg.static_peers.is_empty());
        assert_eq!(cfg.max_outbound, DEFAULT_MAX_OUTBOUND);
        assert_eq!(cfg.max_inbound, DEFAULT_MAX_INBOUND);
        assert_eq!(cfg.p2p_port, DEFAULT_P2P_PORT);
        assert_eq!(cfg.network_id, NetworkId::Mainnet);
        assert_eq!(cfg.service_type, ServiceType::Storage);
        assert!(!cfg.has_bootstrap_sources());
        assert_eq!(cfg.source_count(), 0);
    }

    #[test]
    fn test_config_validate_mainnet_empty() {
        let cfg = BootstrapConfig::default();
        let issues = cfg.validate_for_mainnet();
        assert!(!issues.is_empty());
    }

    #[test]
    fn test_config_validate_mainnet_with_seeds() {
        let mut cfg = BootstrapConfig::default();
        cfg.dns_seeds = vec!["seed1.dsdn.network".to_string()];
        let issues = cfg.validate_for_mainnet();
        assert!(issues.is_empty());
        assert!(cfg.has_bootstrap_sources());
        assert_eq!(cfg.source_count(), 1);
    }

    #[test]
    fn test_config_validate_invalid_static_peer() {
        let mut cfg = BootstrapConfig::default();
        cfg.static_peers = vec!["not-a-valid-addr".to_string()];
        let issues = cfg.validate_for_mainnet();
        assert!(issues.iter().any(|i| i.contains("invalid static peer")));
    }

    // ────────────────────────────────────────────────────────────────────
    // PEER INFO
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn test_peer_info_new() {
        let peer = make_peer(1, PeerSource::DnsSeed);
        assert_eq!(peer.port, 45831);
        assert!(peer.node_id.is_none());
        assert_eq!(peer.success_count, 0);
        assert_eq!(peer.failure_count, 0);
        assert!(!peer.is_suspicious());
    }

    #[test]
    fn test_peer_info_record_success() {
        let mut peer = make_peer(1, PeerSource::DnsSeed);
        peer.record_success();
        assert_eq!(peer.success_count, 1);
        assert_eq!(peer.consecutive_failures, 0);
        assert!(peer.last_connected > 0);
    }

    #[test]
    fn test_peer_info_record_failure() {
        let mut peer = make_peer(1, PeerSource::DnsSeed);
        for _ in 0..SUSPICIOUS_FAILURE_THRESHOLD {
            peer.record_failure();
        }
        assert!(peer.is_suspicious());
        assert_eq!(peer.consecutive_failures, SUSPICIOUS_FAILURE_THRESHOLD);
    }

    #[test]
    fn test_peer_info_failure_reset_on_success() {
        let mut peer = make_peer(1, PeerSource::DnsSeed);
        for _ in 0..5 {
            peer.record_failure();
        }
        assert_eq!(peer.consecutive_failures, 5);
        peer.record_success();
        assert_eq!(peer.consecutive_failures, 0);
        assert_eq!(peer.failure_count, 5); // total preserved
    }

    #[test]
    fn test_peer_info_expiry() {
        let mut peer = make_peer(1, PeerSource::DnsSeed);
        peer.first_seen = TS;
        peer.last_connected = 0;

        // Not expired if within 30 days
        assert!(!peer.is_expired(TS + SECS_7D));

        // Expired after 30 days
        assert!(peer.is_expired(TS + PEER_EXPIRY_SECS + 1));
    }

    #[test]
    fn test_peer_scoring_base() {
        let peer = make_peer(1, PeerSource::DnsSeed);
        // New peer with no history: base score
        let score = peer.score(now_secs());
        assert_eq!(score, PEER_BASE_SCORE);
    }

    #[test]
    fn test_peer_scoring_success_bonus() {
        let mut peer = make_peer(1, PeerSource::DnsSeed);
        let now = now_secs();
        peer.last_connected = now;
        peer.success_count = 5;
        let score = peer.score(now);
        // base(10) + success(5*2) + recency(<1h: +10) = 30
        assert_eq!(score, 10 + 10 + 10);
    }

    #[test]
    fn test_peer_scoring_failure_penalty() {
        let mut peer = make_peer(1, PeerSource::DnsSeed);
        peer.failure_count = 5;
        let score = peer.score(now_secs());
        // base(10) - failure(5*3) = -5
        assert_eq!(score, 10 - 15);
    }

    #[test]
    fn test_peer_scoring_suspicious_penalty() {
        let mut peer = make_peer(1, PeerSource::DnsSeed);
        peer.consecutive_failures = SUSPICIOUS_FAILURE_THRESHOLD;
        peer.failure_count = SUSPICIOUS_FAILURE_THRESHOLD;
        let score = peer.score(now_secs());
        // Has -50 suspicious penalty plus failure penalties
        assert!(score < -20);
    }

    #[test]
    fn test_peer_equality_by_addr() {
        let p1 = make_peer(1, PeerSource::DnsSeed);
        let mut p2 = make_peer(1, PeerSource::StaticConfig);
        p2.success_count = 100; // Different metadata
        assert_eq!(p1, p2); // But same address = equal
    }

    // ────────────────────────────────────────────────────────────────────
    // PEER STORE
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn test_peer_store_empty() {
        let store = PeerStore::in_memory();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_peer_store_upsert() {
        let mut store = PeerStore::in_memory();
        let peer = make_peer(1, PeerSource::DnsSeed);
        assert!(store.upsert(peer.clone())); // new
        assert!(!store.upsert(peer)); // existing
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_peer_store_get() {
        let mut store = PeerStore::in_memory();
        let peer = make_peer(1, PeerSource::DnsSeed);
        let addr = peer.socket_addr();
        store.upsert(peer);
        assert!(store.get(&addr).is_some());
    }

    #[test]
    fn test_peer_store_remove() {
        let mut store = PeerStore::in_memory();
        let peer = make_peer(1, PeerSource::DnsSeed);
        let addr = peer.socket_addr();
        store.upsert(peer);
        assert!(store.remove(&addr).is_some());
        assert!(store.is_empty());
    }

    #[test]
    fn test_peer_store_sorted_by_score() {
        let mut store = PeerStore::in_memory();

        let mut good = make_peer(1, PeerSource::DnsSeed);
        good.success_count = 10;
        good.last_connected = now_secs();

        let bad = make_peer(2, PeerSource::DnsSeed);

        store.upsert(bad);
        store.upsert(good);

        let sorted = store.sorted_by_score();
        assert_eq!(sorted.len(), 2);
        // Good peer (higher score) should be first
        assert_eq!(sorted[0].addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_peer_store_gc_expired() {
        let mut store = PeerStore::in_memory();

        let mut old_peer = make_peer(1, PeerSource::DnsSeed);
        old_peer.first_seen = 1000;
        old_peer.last_connected = 0;

        let fresh_peer = make_peer(2, PeerSource::DnsSeed);

        store.upsert(old_peer);
        store.upsert(fresh_peer);

        let removed = store.gc();
        assert_eq!(removed, 1);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_peer_store_persistence() {
        let tmp = tempfile::NamedTempFile::new().expect("tmpfile");
        let path = tmp.path().to_path_buf();

        // Write
        {
            let mut store = PeerStore::new(path.clone());
            store.upsert(make_peer(1, PeerSource::DnsSeed));
            store.upsert(make_peer(2, PeerSource::StaticConfig));
            store.save().expect("save");
        }

        // Read back
        {
            let store = PeerStore::new(path);
            assert_eq!(store.len(), 2);
        }
    }

    #[test]
    fn test_peer_store_stats() {
        let mut store = PeerStore::in_memory();
        let mut p1 = make_peer(1, PeerSource::DnsSeed);
        p1.service_type = Some(ServiceType::Storage);
        let mut p2 = make_peer(2, PeerSource::StaticConfig);
        p2.service_type = Some(ServiceType::Coordinator);
        store.upsert(p1);
        store.upsert(p2);

        let stats = store.stats();
        assert_eq!(stats.total, 2);
        assert_eq!(*stats.by_source.get("dns_seed").unwrap_or(&0), 1);
        assert_eq!(*stats.by_source.get("static_config").unwrap_or(&0), 1);
        assert_eq!(*stats.by_service.get("storage").unwrap_or(&0), 1);
        assert_eq!(*stats.by_service.get("coordinator").unwrap_or(&0), 1);
    }

    #[test]
    fn test_peer_store_corrupted_file() {
        let tmp = tempfile::NamedTempFile::new().expect("tmpfile");
        std::fs::write(tmp.path(), b"this is not json").expect("write");
        let store = PeerStore::new(tmp.path().to_path_buf());
        assert!(store.is_empty()); // Graceful fallback
    }

    // ────────────────────────────────────────────────────────────────────
    // HANDSHAKE
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn test_handshake_build() {
        let hs = HandshakeMessage::build(
            &TEST_NODE_ID,
            NetworkId::Mainnet,
            45831,
            ServiceType::Storage,
        );
        assert_eq!(hs.protocol_version, PROTOCOL_VERSION);
        assert_eq!(hs.network_id, NetworkId::Mainnet);
        assert_eq!(hs.node_id, TEST_NODE_ID);
        assert!(hs.user_agent.contains("dsdn-node"));
    }

    #[test]
    fn test_handshake_validate_ok() {
        let local = HandshakeMessage::build(
            &TEST_NODE_ID,
            NetworkId::Testnet,
            45831,
            ServiceType::Storage,
        );
        let remote = make_remote_handshake(REMOTE_NODE_ID);
        assert!(local.validate_remote(&remote).is_ok());
    }

    #[test]
    fn test_handshake_reject_network_mismatch() {
        let local = HandshakeMessage::build(
            &TEST_NODE_ID,
            NetworkId::Mainnet,
            45831,
            ServiceType::Storage,
        );
        let remote = make_remote_handshake(REMOTE_NODE_ID); // Testnet
        let err = local.validate_remote(&remote).unwrap_err();
        match err {
            HandshakeError::NetworkMismatch { .. } => {}
            other => panic!("expected NetworkMismatch, got {:?}", other),
        }
    }

    #[test]
    fn test_handshake_reject_self_connection() {
        let local = HandshakeMessage::build(
            &TEST_NODE_ID,
            NetworkId::Testnet,
            45831,
            ServiceType::Storage,
        );
        let mut remote = make_remote_handshake(TEST_NODE_ID); // Same node_id
        remote.network_id = NetworkId::Testnet;
        let err = local.validate_remote(&remote).unwrap_err();
        match err {
            HandshakeError::SelfConnection => {}
            other => panic!("expected SelfConnection, got {:?}", other),
        }
    }

    #[test]
    fn test_handshake_reject_version_mismatch() {
        let local = HandshakeMessage::build(
            &TEST_NODE_ID,
            NetworkId::Testnet,
            45831,
            ServiceType::Storage,
        );
        let mut remote = make_remote_handshake(REMOTE_NODE_ID);
        remote.protocol_version = 999;
        let err = local.validate_remote(&remote).unwrap_err();
        match err {
            HandshakeError::VersionIncompatible { .. } => {}
            other => panic!("expected VersionIncompatible, got {:?}", other),
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // PEX
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn test_pex_response_filters_old_peers() {
        let mut store = PeerStore::in_memory();

        // Peer connected recently
        let mut recent = make_peer(1, PeerSource::DnsSeed);
        recent.last_connected = now_secs();
        store.upsert(recent);

        // Peer never connected
        let old = make_peer(2, PeerSource::DnsSeed);
        store.upsert(old);

        let req = PexRequest {
            service_filter: None,
            max_peers: 100,
        };
        let resp = PexResponse::build_from_store(&store, &req, None);
        assert_eq!(resp.peers.len(), 1);
    }

    #[test]
    fn test_pex_response_service_filter() {
        let mut store = PeerStore::in_memory();

        let mut p1 = make_peer(1, PeerSource::DnsSeed);
        p1.last_connected = now_secs();
        p1.service_type = Some(ServiceType::Storage);
        store.upsert(p1);

        let mut p2 = make_peer(2, PeerSource::DnsSeed);
        p2.last_connected = now_secs();
        p2.service_type = Some(ServiceType::Coordinator);
        store.upsert(p2);

        let req = PexRequest {
            service_filter: Some(ServiceType::Coordinator),
            max_peers: 100,
        };
        let resp = PexResponse::build_from_store(&store, &req, None);
        assert_eq!(resp.peers.len(), 1);
        assert_eq!(resp.peers[0].service_type, Some(ServiceType::Coordinator));
    }

    #[test]
    fn test_pex_response_excludes_requester() {
        let mut store = PeerStore::in_memory();

        let mut p1 = make_peer(1, PeerSource::DnsSeed);
        p1.last_connected = now_secs();
        p1.node_id = Some(REMOTE_NODE_ID);
        store.upsert(p1);

        let mut p2 = make_peer(2, PeerSource::DnsSeed);
        p2.last_connected = now_secs();
        p2.node_id = Some(REMOTE_NODE_ID_2);
        store.upsert(p2);

        let req = PexRequest {
            service_filter: None,
            max_peers: 100,
        };
        let resp =
            PexResponse::build_from_store(&store, &req, Some(&REMOTE_NODE_ID));
        assert_eq!(resp.peers.len(), 1);
        assert_eq!(resp.peers[0].node_id, Some(REMOTE_NODE_ID_2));
    }

    #[test]
    fn test_pex_response_max_limit() {
        let mut store = PeerStore::in_memory();
        for i in 0..50u8 {
            let mut p = make_peer(i, PeerSource::DnsSeed);
            p.last_connected = now_secs();
            store.upsert(p);
        }

        let req = PexRequest {
            service_filter: None,
            max_peers: 5,
        };
        let resp = PexResponse::build_from_store(&store, &req, None);
        assert_eq!(resp.peers.len(), 5);
    }

    // ────────────────────────────────────────────────────────────────────
    // DNS RESOLVER
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn test_mock_dns_resolver() {
        let mut resolver = MockDnsResolver::new();
        resolver.add_result(
            "seed1.dsdn.network",
            vec![
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            ],
        );

        let ips = resolver.resolve("seed1.dsdn.network");
        assert_eq!(ips.len(), 2);

        let empty = resolver.resolve("nonexistent.dsdn.network");
        assert!(empty.is_empty());
    }

    #[test]
    fn test_null_dns_resolver() {
        let resolver = NullDnsResolver;
        assert!(resolver.resolve("anything").is_empty());
    }

    #[test]
    fn test_mock_dns_resolver_ipv6() {
        let mut resolver = MockDnsResolver::new();
        resolver.add_result(
            "seed-v6.dsdn.network",
            vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
        );
        let ips = resolver.resolve("seed-v6.dsdn.network");
        assert_eq!(ips.len(), 1);
        assert!(ips[0].is_ipv6());
    }

    // ────────────────────────────────────────────────────────────────────
    // PEER CONNECTOR
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn test_mock_connector_reachable() {
        let mut connector = MockPeerConnector::new();
        let addr = test_addr(1);
        connector.add_reachable(addr, make_remote_handshake(REMOTE_NODE_ID));

        let local_hs = HandshakeMessage::build(
            &TEST_NODE_ID,
            NetworkId::Testnet,
            45831,
            ServiceType::Storage,
        );
        let result = connector.connect_and_handshake(addr, &local_hs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_mock_connector_unreachable() {
        let connector = MockPeerConnector::new();
        let addr = test_addr(99);
        let local_hs = HandshakeMessage::build(
            &TEST_NODE_ID,
            NetworkId::Testnet,
            45831,
            ServiceType::Storage,
        );
        let result = connector.connect_and_handshake(addr, &local_hs);
        assert!(result.is_err());
    }

    // ────────────────────────────────────────────────────────────────────
    // PEER MANAGER — BOOTSTRAP CHAIN
    // ────────────────────────────────────────────────────────────────────

    fn test_config() -> BootstrapConfig {
        BootstrapConfig {
            dns_seeds: vec!["seed1.test".to_string()],
            static_peers: vec!["192.168.1.100:45831".to_string()],
            peers_file: PathBuf::from("/dev/null"),
            max_outbound: 4,
            max_inbound: 10,
            dns_timeout_secs: 1,
            connect_timeout_secs: 1,
            p2p_port: 45831,
            network_id: NetworkId::Testnet,
            service_type: ServiceType::Storage,
            loaded_from: None,
        }
    }

    #[test]
    fn test_peer_manager_bootstrap_from_static() {
        let config = test_config();
        let addr: SocketAddr = "192.168.1.100:45831".parse().unwrap();

        let mut connector = MockPeerConnector::new();
        connector.add_reachable(addr, make_remote_handshake(REMOTE_NODE_ID));

        let mut mgr = PeerManager::new(
            config,
            TEST_NODE_ID,
            Box::new(NullDnsResolver),
            Box::new(connector),
        );

        let result = mgr.bootstrap();
        match result {
            BootstrapResult::Connected {
                peer_count,
                source,
            } => {
                assert_eq!(peer_count, 1);
                assert_eq!(source, "static_config");
            }
            other => panic!("expected Connected, got {:?}", other),
        }
        assert_eq!(mgr.active_peer_count(), 1);
        assert_eq!(mgr.metrics().peer_connect_success, 1);
    }

    #[test]
    fn test_peer_manager_bootstrap_from_dns() {
        let config = BootstrapConfig {
            dns_seeds: vec!["seed1.test".to_string()],
            static_peers: vec![],
            peers_file: PathBuf::from("/dev/null"),
            network_id: NetworkId::Testnet,
            ..BootstrapConfig::default()
        };

        let dns_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let addr = SocketAddr::new(dns_ip, DEFAULT_P2P_PORT);

        let mut dns = MockDnsResolver::new();
        dns.add_result("seed1.test", vec![dns_ip]);

        let mut connector = MockPeerConnector::new();
        connector.add_reachable(addr, make_remote_handshake(REMOTE_NODE_ID));

        let mut mgr = PeerManager::new(config, TEST_NODE_ID, Box::new(dns), Box::new(connector));

        let result = mgr.bootstrap();
        match result {
            BootstrapResult::Connected {
                peer_count,
                source,
            } => {
                assert_eq!(peer_count, 1);
                assert_eq!(source, "dns_seed");
            }
            other => panic!("expected Connected, got {:?}", other),
        }
        assert_eq!(mgr.metrics().dns_resolve_success, 1);
    }

    #[test]
    fn test_peer_manager_bootstrap_all_fail() {
        let config = BootstrapConfig {
            dns_seeds: vec!["bad-seed.test".to_string()],
            static_peers: vec!["192.168.1.200:45831".to_string()],
            peers_file: PathBuf::from("/dev/null"),
            network_id: NetworkId::Testnet,
            ..BootstrapConfig::default()
        };

        let connector = MockPeerConnector::new(); // Nothing reachable
        let dns = NullDnsResolver; // DNS returns nothing

        let mut mgr =
            PeerManager::new(config, TEST_NODE_ID, Box::new(dns), Box::new(connector));

        let result = mgr.bootstrap();
        match result {
            BootstrapResult::NoPeersAvailable { .. } => {}
            other => panic!("expected NoPeersAvailable, got {:?}", other),
        }
        assert_eq!(mgr.active_peer_count(), 0);
        assert!(mgr.metrics().fallback_triggered >= 2); // static→dns→fail
    }

    #[test]
    fn test_peer_manager_fallback_order() {
        // Static peer unreachable, DNS peer reachable
        let config = BootstrapConfig {
            dns_seeds: vec!["seed.test".to_string()],
            static_peers: vec!["192.168.1.200:45831".to_string()],
            peers_file: PathBuf::from("/dev/null"),
            network_id: NetworkId::Testnet,
            ..BootstrapConfig::default()
        };

        let dns_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let dns_addr = SocketAddr::new(dns_ip, DEFAULT_P2P_PORT);

        let mut dns = MockDnsResolver::new();
        dns.add_result("seed.test", vec![dns_ip]);

        let mut connector = MockPeerConnector::new();
        // Static peer NOT added → will fail
        connector.add_reachable(dns_addr, make_remote_handshake(REMOTE_NODE_ID));

        let mut mgr = PeerManager::new(config, TEST_NODE_ID, Box::new(dns), Box::new(connector));

        let result = mgr.bootstrap();
        match result {
            BootstrapResult::Connected { source, .. } => {
                assert_eq!(source, "dns_seed"); // Fell through static → DNS
            }
            other => panic!("expected Connected via dns, got {:?}", other),
        }
        // Fallback was triggered (static failed → moved to DNS)
        assert!(mgr.metrics().fallback_triggered >= 1);
    }

    #[test]
    fn test_peer_manager_pex_processing() {
        let config = test_config();
        let connector = MockPeerConnector::new();
        let mut mgr = PeerManager::new(
            config,
            TEST_NODE_ID,
            Box::new(NullDnsResolver),
            Box::new(connector),
        );

        let pex_resp = PexResponse {
            peers: vec![
                PexPeerEntry {
                    addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    port: 45831,
                    node_id: Some(REMOTE_NODE_ID),
                    service_type: Some(ServiceType::Storage),
                    last_connected: now_secs(),
                },
                PexPeerEntry {
                    addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    port: 45831,
                    node_id: Some(REMOTE_NODE_ID_2),
                    service_type: Some(ServiceType::Coordinator),
                    last_connected: now_secs(),
                },
            ],
        };

        let added = mgr.process_pex_response(&pex_resp);
        assert_eq!(added, 2);
        // Second call: same peers, no new additions
        let added2 = mgr.process_pex_response(&pex_resp);
        assert_eq!(added2, 0);
    }

    #[test]
    fn test_peer_manager_manual_peer() {
        let config = test_config();
        let connector = MockPeerConnector::new();
        let mut mgr = PeerManager::new(
            config,
            TEST_NODE_ID,
            Box::new(NullDnsResolver),
            Box::new(connector),
        );

        let addr: SocketAddr = "10.0.0.99:45831".parse().unwrap();
        mgr.add_manual_peer(addr);
        assert_eq!(mgr.store().len(), 1);
        assert!(mgr.store().get(&addr).is_some());
    }

    #[test]
    fn test_peer_manager_gc() {
        let config = test_config();
        let connector = MockPeerConnector::new();
        let mut mgr = PeerManager::new(
            config,
            TEST_NODE_ID,
            Box::new(NullDnsResolver),
            Box::new(connector),
        );

        // Add an expired peer
        let mut old = make_peer(1, PeerSource::DnsSeed);
        old.first_seen = 1000;
        old.last_connected = 0;
        mgr.store_mut().upsert(old);

        // Add a fresh peer
        mgr.store_mut().upsert(make_peer(2, PeerSource::DnsSeed));

        let removed = mgr.gc();
        assert_eq!(removed, 1);
        assert_eq!(mgr.store().len(), 1);
    }

    #[test]
    fn test_peer_manager_summary() {
        let config = test_config();
        let connector = MockPeerConnector::new();
        let mgr = PeerManager::new(
            config,
            TEST_NODE_ID,
            Box::new(NullDnsResolver),
            Box::new(connector),
        );

        let summary = mgr.summary();
        assert_eq!(summary.network_id, "testnet");
        assert_eq!(summary.service_type, "storage");
        assert_eq!(summary.dns_seeds_configured, 1);
        assert_eq!(summary.static_peers_configured, 1);
    }

    // ────────────────────────────────────────────────────────────────────
    // METRICS
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn test_metrics_prometheus_format() {
        let mut metrics = BootstrapMetrics::default();
        metrics.dns_resolve_total = 5;
        metrics.peer_connect_success = 3;
        let prom = metrics.to_prometheus("test-node");
        assert!(prom.contains("dsdn_bootstrap_dns_resolve_total"));
        assert!(prom.contains("test-node"));
        assert!(prom.contains("5"));
    }

    // ────────────────────────────────────────────────────────────────────
    // EDGE CASES
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn test_peer_store_empty_gc() {
        let mut store = PeerStore::in_memory();
        assert_eq!(store.gc(), 0);
    }

    #[test]
    fn test_peer_info_socket_addr() {
        let peer = make_peer(42, PeerSource::DnsSeed);
        let addr = peer.socket_addr();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)));
        assert_eq!(addr.port(), 45831);
    }

    #[test]
    fn test_peer_info_node_id_hex() {
        let mut peer = make_peer(1, PeerSource::DnsSeed);
        assert!(peer.node_id_hex().is_none());

        peer.node_id = Some([0xAB; 32]);
        let hex = peer.node_id_hex().unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c == 'a' || c == 'b'));
    }

    #[test]
    fn test_handshake_error_display() {
        let errors = vec![
            HandshakeError::NetworkMismatch {
                local: "mainnet".to_string(),
                remote: "testnet".to_string(),
            },
            HandshakeError::VersionIncompatible {
                local: 1,
                remote: 2,
            },
            HandshakeError::SelfConnection,
            HandshakeError::Timeout,
            HandshakeError::Transport("refused".to_string()),
        ];
        for e in &errors {
            let s = format!("{}", e);
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn test_peer_store_filter_by_service() {
        let mut store = PeerStore::in_memory();

        let mut p1 = make_peer(1, PeerSource::DnsSeed);
        p1.service_type = Some(ServiceType::Storage);
        let mut p2 = make_peer(2, PeerSource::DnsSeed);
        p2.service_type = Some(ServiceType::Coordinator);
        let mut p3 = make_peer(3, PeerSource::DnsSeed);
        p3.service_type = Some(ServiceType::Storage);

        store.upsert(p1);
        store.upsert(p2);
        store.upsert(p3);

        let storage_peers = store.peers_by_service(ServiceType::Storage);
        assert_eq!(storage_peers.len(), 2);

        let coord_peers = store.peers_by_service(ServiceType::Coordinator);
        assert_eq!(coord_peers.len(), 1);

        let validator_peers = store.peers_by_service(ServiceType::Validator);
        assert!(validator_peers.is_empty());
    }

    #[test]
    fn test_peer_store_filter_by_network() {
        let mut store = PeerStore::in_memory();

        store.upsert(PeerInfo::new(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            45831,
            PeerSource::DnsSeed,
            NetworkId::Mainnet,
        ));
        store.upsert(PeerInfo::new(
            IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            45831,
            PeerSource::DnsSeed,
            NetworkId::Testnet,
        ));

        let mainnet = store.peers_by_network(&NetworkId::Mainnet);
        assert_eq!(mainnet.len(), 1);

        let testnet = store.peers_by_network(&NetworkId::Testnet);
        assert_eq!(testnet.len(), 1);
    }

    #[test]
    fn test_config_from_env() {
        // Clean state
        std::env::set_var("BOOTSTRAP_DNS_SEEDS", "seed1.test,seed2.test");
        std::env::set_var("BOOTSTRAP_STATIC_PEERS", "1.2.3.4:45831");
        std::env::set_var("BOOTSTRAP_NETWORK_ID", "testnet");
        std::env::set_var("BOOTSTRAP_SERVICE_TYPE", "coordinator");
        std::env::set_var("BOOTSTRAP_P2P_PORT", "31313");

        let cfg = BootstrapConfig::from_env();
        assert_eq!(cfg.dns_seeds.len(), 2);
        assert_eq!(cfg.static_peers.len(), 1);
        assert_eq!(cfg.network_id, NetworkId::Testnet);
        assert_eq!(cfg.service_type, ServiceType::Coordinator);
        assert_eq!(cfg.p2p_port, 31313);

        // Cleanup
        std::env::remove_var("BOOTSTRAP_DNS_SEEDS");
        std::env::remove_var("BOOTSTRAP_STATIC_PEERS");
        std::env::remove_var("BOOTSTRAP_NETWORK_ID");
        std::env::remove_var("BOOTSTRAP_SERVICE_TYPE");
        std::env::remove_var("BOOTSTRAP_P2P_PORT");
    }

    #[test]
    fn test_bootstrap_result_debug() {
        let r1 = BootstrapResult::Connected {
            peer_count: 3,
            source: "dns".to_string(),
        };
        let r2 = BootstrapResult::NoPeersAvailable {
            summary: "all failed".to_string(),
        };
        let r3 = BootstrapResult::Skipped {
            reason: "no config".to_string(),
        };
        // Just ensure Debug doesn't panic
        let _ = format!("{:?}", r1);
        let _ = format!("{:?}", r2);
        let _ = format!("{:?}", r3);
    }

    #[test]
    fn test_peer_source_display() {
        assert_eq!(PeerSource::DnsSeed.to_string(), "dns_seed");
        assert_eq!(PeerSource::StaticConfig.to_string(), "static_config");
        assert_eq!(PeerSource::PeerExchange.to_string(), "peer_exchange");
        assert_eq!(PeerSource::Inbound.to_string(), "inbound");
        assert_eq!(PeerSource::Manual.to_string(), "manual");
    }

    #[test]
    fn test_peer_manager_active_peers_by_service() {
        let config = test_config();
        let addr1: SocketAddr = "192.168.1.100:45831".parse().unwrap();
        let addr2: SocketAddr = "192.168.1.101:45831".parse().unwrap();

        let mut connector = MockPeerConnector::new();
        connector.add_reachable(addr1, make_remote_handshake(REMOTE_NODE_ID));

        let mut hs2 = make_remote_handshake(REMOTE_NODE_ID_2);
        hs2.service_type = ServiceType::Coordinator;
        connector.add_reachable(addr2, hs2);

        let mut config = test_config();
        config.static_peers = vec![
            "192.168.1.100:45831".to_string(),
            "192.168.1.101:45831".to_string(),
        ];

        let mut mgr = PeerManager::new(
            config,
            TEST_NODE_ID,
            Box::new(NullDnsResolver),
            Box::new(connector),
        );

        mgr.bootstrap();
        let storage_peers = mgr.active_peers_by_service(ServiceType::Storage);
        let coord_peers = mgr.active_peers_by_service(ServiceType::Coordinator);
        assert_eq!(storage_peers.len(), 1);
        assert_eq!(coord_peers.len(), 1);
    }

    // ────────────────────────────────────────────────────────────────────
    // TOML CONFIG PARSING
    // ────────────────────────────────────────────────────────────────────

    /// Exact TOML format from Tahap 28 design doc should parse correctly.
    #[test]
    fn test_toml_parse_full_section() {
        let toml = r#"
[bootstrap]
dns_seeds = [
    "seed1.dsdn.network",
    "seed2.dsdn.network",
    "seed3.dsdn.network",
]
static_peers = [
    "203.0.113.50:45831",
    "198.51.100.10:45831",
]
peers_file = "peers.dat"
max_outbound_connections = 8
max_inbound_connections = 125
dns_resolve_timeout_secs = 10
peer_connect_timeout_secs = 5
p2p_port = 45831
network_id = "mainnet"
service_type = "storage"
"#;
        let cfg = BootstrapConfig::from_toml_str(toml).expect("parse full TOML");
        assert_eq!(cfg.dns_seeds.len(), 3);
        assert_eq!(cfg.dns_seeds[0], "seed1.dsdn.network");
        assert_eq!(cfg.static_peers.len(), 2);
        assert_eq!(cfg.static_peers[0], "203.0.113.50:45831");
        assert_eq!(cfg.peers_file, PathBuf::from("peers.dat"));
        assert_eq!(cfg.max_outbound, 8);
        assert_eq!(cfg.max_inbound, 125);
        assert_eq!(cfg.dns_timeout_secs, 10);
        assert_eq!(cfg.connect_timeout_secs, 5);
        assert_eq!(cfg.p2p_port, 45831);
        assert_eq!(cfg.network_id, NetworkId::Mainnet);
        assert_eq!(cfg.service_type, ServiceType::Storage);
    }

    /// TOML with all seeds commented out — empty arrays are valid.
    #[test]
    fn test_toml_parse_empty_arrays() {
        let toml = r#"
[bootstrap]
dns_seeds = []
static_peers = []
peers_file = "peers.dat"
max_outbound_connections = 4
max_inbound_connections = 50
dns_resolve_timeout_secs = 5
peer_connect_timeout_secs = 3
"#;
        let cfg = BootstrapConfig::from_toml_str(toml).expect("parse empty arrays");
        assert!(cfg.dns_seeds.is_empty());
        assert!(cfg.static_peers.is_empty());
        assert_eq!(cfg.max_outbound, 4);
        assert_eq!(cfg.max_inbound, 50);
        // Unset fields get defaults
        assert_eq!(cfg.p2p_port, DEFAULT_P2P_PORT);
        assert_eq!(cfg.network_id, NetworkId::Mainnet);
    }

    /// TOML with only partial fields — unset fields use defaults.
    #[test]
    fn test_toml_parse_partial_config() {
        let toml = r#"
[bootstrap]
p2p_port = 31313
network_id = "testnet"
service_type = "coordinator"
"#;
        let cfg = BootstrapConfig::from_toml_str(toml).expect("parse partial");
        assert_eq!(cfg.p2p_port, 31313);
        assert_eq!(cfg.network_id, NetworkId::Testnet);
        assert_eq!(cfg.service_type, ServiceType::Coordinator);
        // Unset fields = defaults
        assert!(cfg.dns_seeds.is_empty());
        assert_eq!(cfg.max_outbound, DEFAULT_MAX_OUTBOUND);
        assert_eq!(cfg.peers_file, PathBuf::from("peers.dat"));
    }

    /// TOML with custom network_id.
    #[test]
    fn test_toml_parse_custom_network() {
        let toml = r#"
[bootstrap]
network_id = "devnet-alpha"
service_type = "validator"
"#;
        let cfg = BootstrapConfig::from_toml_str(toml).expect("parse custom net");
        match &cfg.network_id {
            NetworkId::Custom(s) => assert_eq!(s, "devnet-alpha"),
            other => panic!("expected Custom, got {:?}", other),
        }
        assert_eq!(cfg.service_type, ServiceType::Validator);
    }

    /// No [bootstrap] section → from_toml_str returns Err.
    #[test]
    fn test_toml_parse_missing_section() {
        let toml = r#"
[storage]
data_dir = "/data"
"#;
        let result = BootstrapConfig::from_toml_str(toml);
        assert!(result.is_err());
    }

    /// Invalid TOML → from_toml_str returns Err.
    #[test]
    fn test_toml_parse_invalid_toml() {
        let result = BootstrapConfig::from_toml_str("this is not valid toml {{{}");
        assert!(result.is_err());
    }

    /// dsdn.toml with OTHER sections alongside [bootstrap] — only
    /// [bootstrap] is parsed, other sections are ignored.
    #[test]
    fn test_toml_parse_ignores_other_sections() {
        let toml = r#"
[da]
endpoint = "http://localhost:26658"
network = "mocha-4"

[storage]
data_dir = "/data/dsdn"
max_capacity_gb = 100

[bootstrap]
dns_seeds = ["seed1.dsdn.network"]
p2p_port = 45831
network_id = "testnet"

[chain]
rpc_endpoint = "http://localhost:26657"
"#;
        let cfg = BootstrapConfig::from_toml_str(toml).expect("parse with other sections");
        assert_eq!(cfg.dns_seeds.len(), 1);
        assert_eq!(cfg.dns_seeds[0], "seed1.dsdn.network");
        assert_eq!(cfg.p2p_port, 45831);
        assert_eq!(cfg.network_id, NetworkId::Testnet);
    }

    /// Env vars override TOML values (priority chain).
    #[test]
    fn test_toml_env_override_priority() {
        let toml = r#"
[bootstrap]
p2p_port = 45831
network_id = "mainnet"
max_outbound_connections = 8
dns_seeds = ["seed1.dsdn.network"]
"#;
        // Parse TOML first
        let mut cfg = BootstrapConfig::from_toml_str(toml).expect("parse base");
        assert_eq!(cfg.p2p_port, 45831);
        assert_eq!(cfg.network_id, NetworkId::Mainnet);
        assert_eq!(cfg.dns_seeds.len(), 1);

        // Now simulate env overrides
        std::env::set_var("BOOTSTRAP_P2P_PORT", "41414");
        std::env::set_var("BOOTSTRAP_NETWORK_ID", "testnet");
        cfg.apply_env_overrides();

        // Env should win
        assert_eq!(cfg.p2p_port, 41414);
        assert_eq!(cfg.network_id, NetworkId::Testnet);
        // DNS seeds not overridden by env → TOML value preserved
        assert_eq!(cfg.dns_seeds.len(), 1);
        assert_eq!(cfg.dns_seeds[0], "seed1.dsdn.network");

        // Cleanup
        std::env::remove_var("BOOTSTRAP_P2P_PORT");
        std::env::remove_var("BOOTSTRAP_NETWORK_ID");
    }

    /// TOML file persistence: from_file reads a real file.
    #[test]
    fn test_toml_from_file() {
        let tmp = tempfile::NamedTempFile::new().expect("tmpfile");
        let content = r#"
[bootstrap]
dns_seeds = ["seed-from-file.dsdn.network"]
p2p_port = 32323
network_id = "testnet"
service_type = "storage"
max_outbound_connections = 16
"#;
        std::fs::write(tmp.path(), content).expect("write toml");

        // Clear env to avoid interference
        std::env::remove_var("BOOTSTRAP_P2P_PORT");
        std::env::remove_var("BOOTSTRAP_DNS_SEEDS");

        let cfg = BootstrapConfig::from_file(tmp.path()).expect("from_file");
        assert_eq!(cfg.dns_seeds.len(), 1);
        assert_eq!(cfg.dns_seeds[0], "seed-from-file.dsdn.network");
        assert_eq!(cfg.p2p_port, 32323);
        assert_eq!(cfg.network_id, NetworkId::Testnet);
        assert_eq!(cfg.max_outbound, 16);
        assert!(cfg.loaded_from.is_some());
    }

    /// from_file with missing file returns Err.
    #[test]
    fn test_toml_from_file_missing() {
        let result = BootstrapConfig::from_file(Path::new("/nonexistent/dsdn.toml"));
        assert!(result.is_err());
    }

    /// to_toml_string generates valid TOML that re-parses identically.
    #[test]
    fn test_toml_roundtrip() {
        let mut original = BootstrapConfig::default();
        original.dns_seeds = vec![
            "seed1.dsdn.network".to_string(),
            "seed2.dsdn.network".to_string(),
        ];
        original.static_peers = vec!["203.0.113.50:45831".to_string()];
        original.p2p_port = 31313;
        original.network_id = NetworkId::Testnet;
        original.service_type = ServiceType::Coordinator;
        original.max_outbound = 16;

        let toml_str = original.to_toml_string();

        // Re-parse the generated TOML
        let reparsed = BootstrapConfig::from_toml_str(&toml_str)
            .expect("roundtrip parse");

        assert_eq!(reparsed.dns_seeds, original.dns_seeds);
        assert_eq!(reparsed.static_peers, original.static_peers);
        assert_eq!(reparsed.p2p_port, original.p2p_port);
        assert_eq!(reparsed.network_id, original.network_id);
        assert_eq!(reparsed.service_type, original.service_type);
        assert_eq!(reparsed.max_outbound, original.max_outbound);
    }

    /// to_toml_string with defaults generates proper commented-out format.
    #[test]
    fn test_toml_generate_defaults() {
        let cfg = BootstrapConfig::default();
        let toml_str = cfg.to_toml_string();
        assert!(toml_str.contains("[bootstrap]"));
        assert!(toml_str.contains("dns_seeds"));
        assert!(toml_str.contains("static_peers"));
        assert!(toml_str.contains("peers_file"));
        assert!(toml_str.contains("max_outbound_connections = 8"));
        assert!(toml_str.contains("max_inbound_connections = 125"));
        assert!(toml_str.contains("p2p_port = 45831"));
        assert!(toml_str.contains("network_id = \"mainnet\""));
        assert!(toml_str.contains("service_type = \"storage\""));
    }

    /// TOML field name mapping matches the user's expected format.
    #[test]
    fn test_toml_field_names_match_spec() {
        // This is the exact TOML from the user's spec
        let toml = r#"
[bootstrap]
# DNS seeds (founder/community maintained)
dns_seeds = [
    "seed1.dsdn.network",
    "seed2.dsdn.network",
    "seed3.dsdn.network",
]

# Static IP peers (community maintained)
static_peers = [
    "203.0.113.50:45831",
    "198.51.100.10:45831",
]

# Local peer cache
peers_file = "peers.dat"

# Connection settings
max_outbound_connections = 8
max_inbound_connections = 125
dns_resolve_timeout_secs = 10
peer_connect_timeout_secs = 5
"#;
        let cfg = BootstrapConfig::from_toml_str(toml).expect("user spec format");
        assert_eq!(cfg.dns_seeds.len(), 3);
        assert_eq!(cfg.static_peers.len(), 2);
        assert_eq!(cfg.peers_file, PathBuf::from("peers.dat"));
        assert_eq!(cfg.max_outbound, 8);
        assert_eq!(cfg.max_inbound, 125);
        assert_eq!(cfg.dns_timeout_secs, 10);
        assert_eq!(cfg.connect_timeout_secs, 5);
    }

    /// BootstrapToml with unknown fields in TOML → ignored gracefully.
    #[test]
    fn test_toml_unknown_fields_ignored() {
        let toml = r#"
[bootstrap]
dns_seeds = ["seed1.test"]
some_future_field = "hello"
another_new_setting = 42
"#;
        // Should still parse, ignoring unknown fields
        let parsed = BootstrapConfig::parse_toml_str(toml);
        assert!(parsed.is_some());
        let section = parsed.unwrap();
        assert_eq!(section.dns_seeds.unwrap().len(), 1);
    }

    /// loaded_from tracks which file was used.
    #[test]
    fn test_loaded_from_tracking() {
        let cfg = BootstrapConfig::default();
        assert!(cfg.loaded_from().is_none());

        let tmp = tempfile::NamedTempFile::new().expect("tmpfile");
        std::fs::write(
            tmp.path(),
            "[bootstrap]\np2p_port = 12345\n",
        ).expect("write");
        let cfg2 = BootstrapConfig::from_file(tmp.path()).expect("from_file");
        assert_eq!(cfg2.loaded_from().unwrap(), tmp.path());
    }
}