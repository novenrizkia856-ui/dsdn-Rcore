//! # Bootstrap Configuration
//!
//! Konfigurasi bootstrap jaringan DSDN. Bisa di-load dari `dsdn.toml`
//! atau menggunakan hardcoded presets.
//!
//! ## Config File Format (root_dsdn/dsdn.toml)
//!
//! ```toml
//! [bootstrap]
//! # Node role and class
//! role = "storage-compute"  # storage-compute | validator | coordinator
//! node_class = "reguler"    # reguler | datacenter (hanya untuk storage-compute)
//!
//! # Network
//! port = 45831
//! network_id = "mainnet"
//!
//! # DNS seeds (founder/community maintained)
//! dns_seeds = [
//!     # "seed1.dsdn.network",
//!     # "seed2.dsdn.network",
//! ]
//!
//! # Static IP peers (community maintained)
//! static_peers = [
//!     # "203.0.113.50:45831",
//!     # "198.51.100.10:45831",
//! ]
//!
//! # Local peer cache
//! peers_file = "peers.dat"
//!
//! # Connection settings
//! max_outbound_connections = 8
//! max_inbound_connections = 125
//! dns_resolve_timeout_secs = 10
//! peer_connect_timeout_secs = 5
//! ```
//!
//! ## Loading Priority
//!
//! 1. `dsdn.toml` di working directory → primary
//! 2. `dsdn.toml` di parent of db_path → fallback
//! 3. Hardcoded defaults → last resort (development mode)

use serde::{Serialize, Deserialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use super::types::{NodeRole, NodeClass};

// ════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════

/// Default port untuk semua role DSDN.
pub const DSDN_DEFAULT_PORT: u16 = 45831;

// ════════════════════════════════════════════════════════════════════════════
// TOML RAW STRUCTS (intermediate for deserialization)
// ════════════════════════════════════════════════════════════════════════════

/// Top-level dsdn.toml structure.
/// Hanya [bootstrap] section yang diparse di sini.
#[derive(Debug, Clone, Deserialize)]
struct DsdnToml {
    bootstrap: Option<BootstrapToml>,
}

/// [bootstrap] section di dsdn.toml.
/// Semua field optional — yang tidak ada pakai default.
#[derive(Debug, Clone, Deserialize)]
struct BootstrapToml {
    // ── Role & Class (NEW) ───────────────────────────
    role: Option<String>,
    node_class: Option<String>,
    port: Option<u16>,
    network_id: Option<String>,
    // ── Seeds & Peers ────────────────────────────────
    dns_seeds: Option<Vec<String>>,
    static_peers: Option<Vec<String>>,
    peers_file: Option<String>,
    // ── Connection limits ────────────────────────────
    max_outbound_connections: Option<u32>,
    max_inbound_connections: Option<u32>,
    dns_resolve_timeout_secs: Option<u64>,
    peer_connect_timeout_secs: Option<u64>,
}

// ════════════════════════════════════════════════════════════════════════════
// DNS SEED
// ════════════════════════════════════════════════════════════════════════════

/// DNS seed entry.
/// Setiap DNS seed di-resolve ke satu atau lebih IP (A/AAAA record).
/// DNS TIDAK role-aware — semua role tercampur di satu record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsSeed {
    pub hostname: String,
    pub port: u16,
    pub is_founder_operated: bool,
}

impl DnsSeed {
    pub fn new(hostname: &str, port: u16) -> Self {
        Self { hostname: hostname.to_string(), port, is_founder_operated: false }
    }

    pub fn founder(hostname: &str, port: u16) -> Self {
        Self { hostname: hostname.to_string(), port, is_founder_operated: true }
    }

    /// Parse dari string "hostname" atau "hostname:port".
    /// Default port = DSDN_DEFAULT_PORT (45831).
    pub fn parse(s: &str) -> Self {
        let s = s.trim();
        if let Some((host, port_str)) = s.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Self::new(host, port);
            }
        }
        Self::new(s, DSDN_DEFAULT_PORT)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// STATIC PEER
// ════════════════════════════════════════════════════════════════════════════

/// Static peer entry (IP:Port).
/// Role tidak diketahui sampai handshake — semua pakai port 45831.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StaticPeer {
    pub addr: SocketAddr,
    pub label: Option<String>,
}

impl StaticPeer {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr, label: None }
    }

    pub fn with_label(addr: SocketAddr, label: &str) -> Self {
        Self { addr, label: Some(label.to_string()) }
    }

    pub fn parse(s: &str) -> Result<Self, anyhow::Error> {
        let s = s.trim();
        // Jika tidak ada port, tambahkan default port
        let addr_str = if s.contains(':') {
            s.to_string()
        } else {
            format!("{}:{}", s, DSDN_DEFAULT_PORT)
        };
        let addr: SocketAddr = addr_str.parse()
            .map_err(|e| anyhow::anyhow!("invalid static peer address '{}': {}", s, e))?;
        Ok(Self::new(addr))
    }
}

// ════════════════════════════════════════════════════════════════════════════
// CONNECTION LIMITS
// ════════════════════════════════════════════════════════════════════════════

/// Batasan koneksi P2P.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionLimits {
    pub max_outbound: u32,
    pub max_inbound: u32,
    pub dns_timeout_secs: u64,
    pub connect_timeout_secs: u64,
    pub retry_interval_secs: u64,
    pub max_peer_store_entries: u32,
    pub peer_max_age_secs: u64,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max_outbound: 8,
            max_inbound: 125,
            dns_timeout_secs: 10,
            connect_timeout_secs: 5,
            retry_interval_secs: 30,
            max_peer_store_entries: 10_000,
            peer_max_age_secs: 30 * 24 * 3600, // 30 hari
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// BOOTSTRAP CONFIG
// ════════════════════════════════════════════════════════════════════════════

/// Konfigurasi lengkap bootstrap system.
///
/// ## Loading
///
/// ```rust,ignore
/// // Dari dsdn.toml (recommended)
/// let config = BootstrapConfig::load_from_project(db_path)?;
///
/// // Dari file spesifik
/// let config = BootstrapConfig::from_toml_file(Path::new("dsdn.toml"))?;
///
/// // Hardcoded preset
/// let config = BootstrapConfig::development();
/// ```
///
/// ## Bootstrap Fallback Order
///
/// ```text
/// 1. peers.dat (local cache, tercepat) → filter by role
/// 2. static_peers (dari config) → connect → handshake → filter by role
/// 3. dns_seeds (DNS resolve) → connect → handshake → filter by role
/// 4. retry dengan backoff
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapConfig {
    // ── Role & Identity (NEW — sesuai Tahap 21 v2) ──
    /// Role operasional node ini
    pub role: NodeRole,
    /// Kelas node — hanya relevan jika role == StorageCompute.
    /// HARUS Some untuk StorageCompute, HARUS None untuk lainnya.
    pub node_class: Option<NodeClass>,
    /// Port listen (selalu 45831 untuk semua role)
    pub port: u16,

    // ── Seeds & Peers ────────────────────────────────
    pub dns_seeds: Vec<DnsSeed>,
    pub static_peers: Vec<StaticPeer>,
    pub peers_file: String,
    pub limits: ConnectionLimits,
    pub enable_pex: bool,
    pub enable_rotation: bool,
    pub pex_interval_secs: u64,
    pub dns_refresh_interval_secs: u64,
    pub store_save_interval_secs: u64,

    /// Path dari mana config ini di-load (None = hardcoded preset)
    #[serde(skip)]
    pub loaded_from: Option<PathBuf>,
}

impl BootstrapConfig {
    // ════════════════════════════════════════════════════════════════════════
    // TOML LOADING — PRIMARY WAY TO CREATE CONFIG
    // ════════════════════════════════════════════════════════════════════════

    /// Load bootstrap config dari dsdn.toml.
    ///
    /// Mencari dsdn.toml di beberapa lokasi:
    /// 1. Working directory (`./dsdn.toml`)
    /// 2. Parent of db_path (`db_path/../dsdn.toml`)
    /// 3. db_path itself (`db_path/dsdn.toml`)
    ///
    /// Jika file tidak ditemukan → return development defaults.
    /// Jika file ditemukan tapi parse gagal → return error (fatal).
    pub fn load_from_project(db_path: &Path) -> anyhow::Result<Self> {
        let candidates = vec![
            PathBuf::from("dsdn.toml"),
            db_path.parent()
                .map(|p| p.join("dsdn.toml"))
                .unwrap_or_else(|| PathBuf::from("dsdn.toml")),
            db_path.join("dsdn.toml"),
        ];

        for candidate in &candidates {
            if candidate.exists() {
                return Self::from_toml_file(candidate);
            }
        }

        println!("   ℹ  No dsdn.toml found, using development defaults for P2P");
        println!("      Searched: {:?}", candidates.iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>());
        Ok(Self::development())
    }

    /// Load dari specific TOML file path.
    pub fn from_toml_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!(
                "failed to read '{}': {}", path.display(), e
            ))?;

        let mut config = Self::from_toml_str(&content)
            .map_err(|e| anyhow::anyhow!(
                "failed to parse '{}': {}", path.display(), e
            ))?;

        config.loaded_from = Some(path.to_path_buf());

        println!("   ✓  Loaded P2P bootstrap config from {}", path.display());
        println!("      Role:         {} {}", config.role,
            config.node_class.map(|c| format!("({})", c)).unwrap_or_default());
        println!("      Port:         {}", config.port);
        println!("      DNS seeds:    {} configured", config.dns_seeds.len());
        println!("      Static peers: {} configured", config.static_peers.len());
        println!("      Peers file:   {}", config.peers_file);
        println!("      Outbound:     {} max", config.limits.max_outbound);
        println!("      Inbound:      {} max", config.limits.max_inbound);

        Ok(config)
    }

    /// Parse dari TOML string. Core parser dipanggil oleh `from_toml_file()`.
    pub fn from_toml_str(toml_content: &str) -> anyhow::Result<Self> {
        let parsed: DsdnToml = toml::from_str(toml_content)
            .map_err(|e| anyhow::anyhow!("TOML parse error: {}", e))?;

        let defaults = Self::development();

        let bootstrap = match parsed.bootstrap {
            Some(b) => b,
            None => return Ok(defaults),
        };

        // ── Parse role & class (NEW) ──────────────────────────────
        let role = match &bootstrap.role {
            Some(r) => NodeRole::from_str_role(r)
                .ok_or_else(|| anyhow::anyhow!(
                    "invalid role '{}'. Valid: storage-compute, validator, coordinator", r
                ))?,
            None => defaults.role,
        };

        let node_class = match &bootstrap.node_class {
            Some(c) => {
                if !role.has_node_class() {
                    anyhow::bail!(
                        "node_class '{}' specified but role '{}' does not support classes. \
                         Only storage-compute has classes (reguler, datacenter).",
                        c, role
                    );
                }
                Some(NodeClass::from_str_class(c)
                    .ok_or_else(|| anyhow::anyhow!(
                        "invalid node_class '{}'. Valid: reguler, datacenter", c
                    ))?)
            }
            None => {
                if role.has_node_class() {
                    // StorageCompute tanpa class → default ke Reguler
                    Some(NodeClass::Reguler)
                } else {
                    None
                }
            }
        };

        let port = bootstrap.port.unwrap_or(DSDN_DEFAULT_PORT);

        // Parse DNS seeds — skip empty strings
        let dns_seeds: Vec<DnsSeed> = bootstrap.dns_seeds
            .unwrap_or_default()
            .into_iter()
            .filter(|s| !s.trim().is_empty())
            .map(|s| DnsSeed::parse(&s))
            .collect();

        // Parse static peers — skip invalid, log warning
        let mut static_peers: Vec<StaticPeer> = vec![];
        for addr_str in bootstrap.static_peers.unwrap_or_default() {
            let trimmed = addr_str.trim();
            if trimmed.is_empty() { continue; }
            match StaticPeer::parse(trimmed) {
                Ok(peer) => static_peers.push(peer),
                Err(e) => {
                    eprintln!("   ⚠️  Skipping invalid static peer '{}': {}", trimmed, e);
                }
            }
        }

        // Build ConnectionLimits: TOML values override defaults
        let limits = ConnectionLimits {
            max_outbound: bootstrap.max_outbound_connections
                .unwrap_or(defaults.limits.max_outbound),
            max_inbound: bootstrap.max_inbound_connections
                .unwrap_or(defaults.limits.max_inbound),
            dns_timeout_secs: bootstrap.dns_resolve_timeout_secs
                .unwrap_or(defaults.limits.dns_timeout_secs),
            connect_timeout_secs: bootstrap.peer_connect_timeout_secs
                .unwrap_or(defaults.limits.connect_timeout_secs),
            retry_interval_secs: defaults.limits.retry_interval_secs,
            max_peer_store_entries: defaults.limits.max_peer_store_entries,
            peer_max_age_secs: defaults.limits.peer_max_age_secs,
        };

        let peers_file = bootstrap.peers_file
            .unwrap_or(defaults.peers_file);

        // Auto-enable PEX/rotation jika ada seed sources
        let has_seeds = !dns_seeds.is_empty() || !static_peers.is_empty();

        Ok(Self {
            role,
            node_class,
            port,
            dns_seeds,
            static_peers,
            peers_file,
            limits,
            enable_pex: has_seeds,
            enable_rotation: has_seeds,
            pex_interval_secs: defaults.pex_interval_secs,
            dns_refresh_interval_secs: defaults.dns_refresh_interval_secs,
            store_save_interval_secs: defaults.store_save_interval_secs,
            loaded_from: None,
        })
    }

    // ════════════════════════════════════════════════════════════════════════
    // HARDCODED PRESETS
    // ════════════════════════════════════════════════════════════════════════

    /// Development/testing — StorageCompute Reguler, no DNS, no static, PEX off.
    pub fn development() -> Self {
        Self {
            role: NodeRole::StorageCompute,
            node_class: Some(NodeClass::Reguler),
            port: DSDN_DEFAULT_PORT,
            dns_seeds: vec![],
            static_peers: vec![],
            peers_file: "peers.dat".to_string(),
            limits: ConnectionLimits::default(),
            enable_pex: false,
            enable_rotation: false,
            pex_interval_secs: 900,
            dns_refresh_interval_secs: 1800,
            store_save_interval_secs: 300,
            loaded_from: None,
        }
    }

    /// Testnet — PEX enabled, no DNS yet.
    pub fn testnet() -> Self {
        Self {
            enable_pex: true,
            enable_rotation: true,
            ..Self::development()
        }
    }

    /// Mainnet — DNS seeds HARUS diisi sebelum launch.
    pub fn mainnet() -> Self {
        Self {
            dns_seeds: vec![
                // UNCOMMENT saat domain sudah dibeli:
                // DnsSeed::founder("seed1.dsdn.network", DSDN_DEFAULT_PORT),
                // DnsSeed::founder("seed2.dsdn.network", DSDN_DEFAULT_PORT),
            ],
            enable_pex: true,
            enable_rotation: true,
            ..Self::development()
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // UTILITIES
    // ════════════════════════════════════════════════════════════════════════

    /// Validasi config. Returns list of warnings/errors.
    pub fn validate(&self) -> Vec<String> {
        let mut w = vec![];

        // Role + class consistency
        match self.role {
            NodeRole::StorageCompute => {
                if self.node_class.is_none() {
                    w.push("ERROR: role=storage-compute requires node_class (reguler or datacenter).".to_string());
                }
            }
            NodeRole::Validator | NodeRole::Coordinator | NodeRole::Bootstrap => {
                if self.node_class.is_some() {
                    w.push(format!(
                        "ERROR: role={} must not have node_class. Remove node_class from config.",
                        self.role
                    ));
                }
            }
        }

        // Port check
        if self.port != DSDN_DEFAULT_PORT {
            w.push(format!(
                "WARNING: port {} differs from DSDN standard port {}. \
                 All roles should use port {}.",
                self.port, DSDN_DEFAULT_PORT, DSDN_DEFAULT_PORT,
            ));
        }

        // Seed check
        if self.dns_seeds.is_empty() && self.static_peers.is_empty() {
            w.push(
                "WARNING: No DNS seeds and no static peers. \
                 Node can only discover peers via manual add or inbound."
                    .to_string(),
            );
        }

        if self.limits.max_outbound == 0 {
            w.push("ERROR: max_outbound is 0, node cannot connect.".to_string());
        }

        for (i, seed) in self.dns_seeds.iter().enumerate() {
            if seed.hostname.is_empty() {
                w.push(format!("ERROR: DNS seed #{} has empty hostname.", i));
            }
        }

        w
    }

    /// Check apakah config cukup untuk mainnet.
    pub fn is_mainnet_ready(&self) -> bool {
        self.dns_seeds.iter().any(|s| s.is_founder_operated)
            && self.enable_pex
            && self.enable_rotation
            && self.port == DSDN_DEFAULT_PORT
            && self.validate().iter().all(|w| !w.starts_with("ERROR"))
    }

    /// Human-readable role string (e.g. "storage-compute (reguler)").
    pub fn role_display(&self) -> String {
        match self.node_class {
            Some(class) => format!("{} ({})", self.role, class),
            None => self.role.to_string(),
        }
    }

    pub fn add_dns_seed(&mut self, hostname: &str, port: u16) {
        self.dns_seeds.push(DnsSeed::new(hostname, port));
    }

    pub fn add_static_peer(&mut self, addr_str: &str) -> Result<(), anyhow::Error> {
        self.static_peers.push(StaticPeer::parse(addr_str)?);
        Ok(())
    }

    pub fn total_seed_sources(&self) -> usize {
        self.dns_seeds.len() + self.static_peers.len()
    }

    pub fn is_from_file(&self) -> bool {
        self.loaded_from.is_some()
    }
}

impl Default for BootstrapConfig {
    fn default() -> Self { Self::development() }
}

// ════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_full_dsdn_toml() {
        let toml = r#"
[bootstrap]
role = "storage-compute"
node_class = "datacenter"
port = 45831
dns_seeds = ["seed1.dsdn.network", "seed2.dsdn.network"]
static_peers = ["203.0.113.50:45831", "198.51.100.10:45831"]
peers_file = "my_peers.dat"
max_outbound_connections = 16
max_inbound_connections = 250
dns_resolve_timeout_secs = 15
peer_connect_timeout_secs = 8
"#;
        let c = BootstrapConfig::from_toml_str(toml).unwrap();
        assert_eq!(c.role, NodeRole::StorageCompute);
        assert_eq!(c.node_class, Some(NodeClass::DataCenter));
        assert_eq!(c.port, DSDN_DEFAULT_PORT);
        assert_eq!(c.dns_seeds.len(), 2);
        assert_eq!(c.dns_seeds[0].hostname, "seed1.dsdn.network");
        assert_eq!(c.dns_seeds[0].port, DSDN_DEFAULT_PORT);
        assert_eq!(c.static_peers.len(), 2);
        assert_eq!(c.peers_file, "my_peers.dat");
        assert_eq!(c.limits.max_outbound, 16);
        assert_eq!(c.limits.max_inbound, 250);
    }

    #[test]
    fn test_parse_validator_config() {
        let toml = r#"
[bootstrap]
role = "validator"
static_peers = ["10.0.0.1:45831"]
"#;
        let c = BootstrapConfig::from_toml_str(toml).unwrap();
        assert_eq!(c.role, NodeRole::Validator);
        assert_eq!(c.node_class, None);
    }

    #[test]
    fn test_parse_coordinator_config() {
        let toml = r#"
[bootstrap]
role = "coordinator"
"#;
        let c = BootstrapConfig::from_toml_str(toml).unwrap();
        assert_eq!(c.role, NodeRole::Coordinator);
        assert_eq!(c.node_class, None);
    }

    #[test]
    fn test_parse_validator_with_class_errors() {
        // Validator TIDAK boleh punya node_class
        let toml = r#"
[bootstrap]
role = "validator"
node_class = "datacenter"
"#;
        let result = BootstrapConfig::from_toml_str(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("does not support classes"));
    }

    #[test]
    fn test_parse_storage_defaults_to_reguler() {
        // StorageCompute tanpa class → default Reguler
        let toml = r#"
[bootstrap]
role = "storage-compute"
"#;
        let c = BootstrapConfig::from_toml_str(toml).unwrap();
        assert_eq!(c.role, NodeRole::StorageCompute);
        assert_eq!(c.node_class, Some(NodeClass::Reguler));
    }

    #[test]
    fn test_parse_default_dsdn_toml_with_empty_seeds() {
        let toml = r#"
[bootstrap]
dns_seeds = []
static_peers = []
peers_file = "peers.dat"
max_outbound_connections = 8
max_inbound_connections = 125
dns_resolve_timeout_secs = 10
peer_connect_timeout_secs = 5
"#;
        let c = BootstrapConfig::from_toml_str(toml).unwrap();
        assert!(c.dns_seeds.is_empty());
        assert!(c.static_peers.is_empty());
        assert_eq!(c.role, NodeRole::StorageCompute); // default
        assert_eq!(c.node_class, Some(NodeClass::Reguler)); // default
        assert!(!c.enable_pex);
    }

    #[test]
    fn test_parse_no_bootstrap_section_returns_defaults() {
        let toml = r#"
[some_other_section]
key = "value"
"#;
        let c = BootstrapConfig::from_toml_str(toml).unwrap();
        assert!(c.dns_seeds.is_empty());
        assert_eq!(c.limits.max_outbound, 8);
        assert_eq!(c.role, NodeRole::StorageCompute);
    }

    #[test]
    fn test_parse_partial_config_fills_defaults() {
        let toml = r#"
[bootstrap]
max_outbound_connections = 32
"#;
        let c = BootstrapConfig::from_toml_str(toml).unwrap();
        assert_eq!(c.limits.max_outbound, 32);
        assert_eq!(c.limits.max_inbound, 125);
        assert_eq!(c.peers_file, "peers.dat");
    }

    #[test]
    fn test_parse_skips_invalid_static_peers() {
        let toml = r#"
[bootstrap]
static_peers = [
    "203.0.113.50:45831",
    "this-is-not-valid",
    "198.51.100.10:45831",
]
"#;
        let c = BootstrapConfig::from_toml_str(toml).unwrap();
        assert_eq!(c.static_peers.len(), 2);
    }

    #[test]
    fn test_dns_seed_parse_with_port() {
        let s = DnsSeed::parse("seed1.dsdn.network:31337");
        assert_eq!(s.hostname, "seed1.dsdn.network");
        assert_eq!(s.port, 31337);
    }

    #[test]
    fn test_dns_seed_parse_default_port() {
        let s = DnsSeed::parse("seed1.dsdn.network");
        assert_eq!(s.port, DSDN_DEFAULT_PORT);
    }

    #[test]
    fn test_auto_enable_pex_when_seeds_present() {
        let toml = r#"
[bootstrap]
static_peers = ["10.0.0.1:45831"]
"#;
        let c = BootstrapConfig::from_toml_str(toml).unwrap();
        assert!(c.enable_pex);
        assert!(c.enable_rotation);
    }

    #[test]
    fn test_invalid_toml_returns_error() {
        assert!(BootstrapConfig::from_toml_str("not valid {{{{").is_err());
    }

    #[test]
    fn test_invalid_role_returns_error() {
        let toml = r#"
[bootstrap]
role = "chain"
"#;
        let result = BootstrapConfig::from_toml_str(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid role"));
    }

    #[test]
    fn test_file_io_roundtrip() {
        let tmp_dir = std::env::temp_dir();
        let tmp = tmp_dir.join("dsdn_test_bootstrap_config.toml");
        let content = r#"
[bootstrap]
role = "validator"
static_peers = ["10.0.0.1:45831"]
peers_file = "test_peers.dat"
max_outbound_connections = 4
"#;
        std::fs::write(&tmp, content).unwrap();
        let c = BootstrapConfig::from_toml_file(&tmp).unwrap();
        assert_eq!(c.role, NodeRole::Validator);
        assert_eq!(c.node_class, None);
        assert_eq!(c.static_peers.len(), 1);
        assert_eq!(c.limits.max_outbound, 4);
        assert!(c.is_from_file());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_development_defaults() {
        let c = BootstrapConfig::development();
        assert!(c.dns_seeds.is_empty());
        assert!(!c.enable_pex);
        assert!(!c.is_from_file());
        assert_eq!(c.role, NodeRole::StorageCompute);
        assert_eq!(c.node_class, Some(NodeClass::Reguler));
        assert_eq!(c.port, DSDN_DEFAULT_PORT);
    }

    #[test]
    fn test_mainnet_not_ready() {
        assert!(!BootstrapConfig::mainnet().is_mainnet_ready());
    }

    #[test]
    fn test_validate_validator_with_class() {
        let mut c = BootstrapConfig::development();
        c.role = NodeRole::Validator;
        c.node_class = Some(NodeClass::DataCenter); // INVALID
        let warnings = c.validate();
        assert!(warnings.iter().any(|w| w.contains("must not have node_class")));
    }

    #[test]
    fn test_validate_storage_without_class() {
        let mut c = BootstrapConfig::development();
        c.role = NodeRole::StorageCompute;
        c.node_class = None; // INVALID
        let warnings = c.validate();
        assert!(warnings.iter().any(|w| w.contains("requires node_class")));
    }

    #[test]
    fn test_role_display() {
        let mut c = BootstrapConfig::development();
        assert_eq!(c.role_display(), "storage-compute (reguler)");

        c.role = NodeRole::Validator;
        c.node_class = None;
        assert_eq!(c.role_display(), "validator");
    }

    #[test]
    fn test_static_peer_parse_without_port() {
        let sp = StaticPeer::parse("10.0.0.1").unwrap();
        assert_eq!(sp.addr.port(), DSDN_DEFAULT_PORT);
    }
}