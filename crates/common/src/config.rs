//! Simple config loader using TOML and serde.
//! The config struct is intentionally small and typed for the initial DSDN prototypes.

use serde::Deserialize;
use std::path::Path;
use std::fs;
use crate::Result;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Optional node id (string). If absent a consumer may generate one.
    pub node_id: Option<String>,

    /// Data directory where node stores objects.
    pub data_dir: Option<String>,

    /// Bind address for RPC (e.g., "127.0.0.1:7000")
    pub bind_addr: Option<String>,

    /// Zone identifier for placement awareness.
    pub zone: Option<String>,

    /// Capacity in GiB (approx) that node reports.
    pub capacity_gb: Option<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            node_id: None,
            data_dir: Some("./data".to_string()),
            bind_addr: Some("127.0.0.1:7000".to_string()),
            zone: Some("default-zone".to_string()),
            capacity_gb: Some(100),
        }
    }
}

/// Load config from a TOML file path.
/// If file is missing or parse fails, an error is returned.
pub fn load_from_file(path: impl AsRef<Path>) -> Result<Config> {
    let p = path.as_ref();
    let s = fs::read_to_string(p)?;
    let cfg: Config = toml::from_str(&s)?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let def = Config::default();
        assert!(def.data_dir.is_some());
        assert!(def.bind_addr.is_some());
    }

    #[test]
    fn test_load_from_file_roundtrip() {
        use std::io::Write;
        let tmp = tempfile::NamedTempFile::new().expect("temp file");
        let toml = r#"
            node_id = "node-xyz"
            data_dir = "./mydata"
            bind_addr = "0.0.0.0:7010"
            zone = "zone-a"
            capacity_gb = 42
        "#;
        let mut f = tmp.reopen().expect("reopen");
        write!(f, "{}", toml).expect("write");
        let path = tmp.path().to_path_buf();
        let cfg = load_from_file(path).expect("load");
        assert_eq!(cfg.node_id.unwrap(), "node-xyz");
        assert_eq!(cfg.capacity_gb.unwrap(), 42);
    }
}
