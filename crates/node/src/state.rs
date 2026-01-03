use std::path::{PathBuf};
use std::fs;
use dsdn_common::cid::sha256_hex;
use std::collections::HashSet;

/// Manage local node state, scanning objects dir and returning list of object hashes.
#[derive(Clone, Debug)]
pub struct NodeState {
    pub node_id: String,
    pub base_dir: PathBuf,
}

impl NodeState {
    pub fn new(node_id: String, base_dir: impl Into<PathBuf>) -> Self {
        NodeState {
            node_id,
            base_dir: base_dir.into(),
        }
    }

    /// Objects directory: <base_dir>/objects
    pub fn objects_dir(&self) -> PathBuf {
        self.base_dir.join("objects")
    }

    /// Collect all object hashes found under objects dir (prefix dirs).
    pub fn list_local_object_hashes(&self) -> anyhow::Result<Vec<String>> {
        let mut out = Vec::new();
        let obj_dir = self.objects_dir();
        if !obj_dir.exists() {
            return Ok(out);
        }
        for entry in fs::read_dir(&obj_dir)? {
            let e = entry?;
            let p = e.path();
            if p.is_dir() {
                // each file inside is full hash
                for f in fs::read_dir(&p)? {
                    let f = f?;
                    let fp = f.path();
                    if fp.is_file() {
                        if let Some(name) = fp.file_name().and_then(|n| n.to_str()) {
                            out.push(name.to_string());
                        }
                    }
                }
            } else if p.is_file() {
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    out.push(name.to_string());
                }
            }
        }
        Ok(out)
    }

    /// Return true if given hash exists locally
    pub fn has_local_hash(&self, hash: &str) -> bool {
        let path = self.objects_dir().join(&hash[0..2]).join(hash);
        path.exists()
    }
}
