




































































































































































































































































































































































































































use std::collections::{HashMap, HashSet};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use std::sync::Arc;
use hex::FromHex;





pub mod quorum_da;
pub mod signature_collector;
pub mod metrics_tracking;


pub mod coordinator_selection;






pub use quorum_da::{

QuorumDA,


ValidatorQuorumDA,


QuorumDAConfig,
ConfigError,


ValidatorInfo,
ValidatorSignature,


QuorumVerification,


QuorumError,
};






pub use signature_collector::{
SignatureCollector,
SignatureCollectionError,
ValidatorEndpoint,
};






pub use metrics_tracking::QuorumMetrics;






pub use coordinator_selection::{

ValidatorCandidate,
SelectionWeight,
CoordinatorMember,
CoordinatorCommittee,
CommitteeInvariantError,
SelectionConfig,


CoordinatorSelector,
SelectorConfigError,


SelectionError,


derive_epoch_seed,


DAMerkleProof,
SeedVerificationResult,
verify_epoch_seed,
verify_merkle_proof,
VerificationError,
verify_committee_selection,
verify_member_eligibility,
};






#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobRef {

pub hash: String,

#[serde(default)]
pub r#type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
pub key_id: String,
pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SBOM {

pub name: Option<String>,
pub license: Option<String>,
pub supplier: Option<String>,
#[serde(flatten)]
pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
pub name: String,
pub version: Option<String>,
pub entrypoint: String,
#[serde(default)]
pub blobs: Vec<BlobRef>,
#[serde(default)]
pub signatures: Vec<Signature>,
#[serde(default)]
pub sbom: Option<SBOM>,
#[serde(default)]
pub meta: HashMap<String, serde_json::Value>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
pub ok: bool,
pub errors: Vec<String>,
pub warnings: Vec<String>,
}

impl ValidationResult {
pub fn ok() -> Self {
Self {
ok: true,
errors: vec![],
warnings: vec![],
}
}

pub fn fail(err: impl Into<String>) -> Self {
Self {
ok: false,
errors: vec![err.into()],
warnings: vec![],
}
}
}


#[derive(Clone)]
pub struct Validator {
banned: Arc<RwLock<HashSet<String>>>,
trusted_keys: Arc<RwLock<HashSet<String>>>,
}

#[derive(Error, Debug)]
pub enum ValidatorError {
#[error("validation internal error: {0}")]
Internal(String),
}

impl Validator {

pub fn new() -> Self {
let mut tk = HashSet::new();
tk.insert("trusted-key".to_string());
Self {
banned: Arc::new(RwLock::new(HashSet::new())),
trusted_keys: Arc::new(RwLock::new(tk)),
}
}


pub fn ban_hash(&self, hash: &str) {
self.banned.write().insert(hash.to_string());
}


pub fn unban_hash(&self, hash: &str) {
self.banned.write().remove(hash);
}


pub fn list_banned(&self) -> Vec<String> {
self.banned.read().iter().cloned().collect()
}


pub fn add_trusted_key(&self, key_id: &str) {
self.trusted_keys.write().insert(key_id.to_string());
}


pub fn remove_trusted_key(&self, key_id: &str) {
self.trusted_keys.write().remove(key_id);
}



pub fn validate_manifest(&self, manifest: &Manifest) -> Result<ValidationResult, ValidatorError> {
let mut res = ValidationResult::ok();


if manifest.name.trim().is_empty() {
res.ok = false;
res.errors.push("manifest.name must not be empty".to_string());
}


if !is_valid_sha256_hex(&manifest.entrypoint) {
res.ok = false;
res.errors.push(format!("entrypoint has invalid sha256 hex: {}", manifest.entrypoint));
}


for b in &manifest.blobs {
if !is_valid_sha256_hex(&b.hash) {
res.ok = false;
res.errors.push(format!("blob has invalid sha256 hex: {}", b.hash));
continue
}
if self.banned.read().contains(&b.hash) {
res.ok = false;
res.errors.push(format!("blob {} is banned", b.hash));
}
}


if !manifest.blobs.iter().any(|b| b.hash == manifest.entrypoint) {
res.warnings.push("entrypoint not listed in blobs; ensure runtime can fetch entrypoint".to_string());
}


if manifest.signatures.is_empty() {
res.warnings.push("no signatures provided for manifest".to_string());
} else {
let mut has_trusted = false;
for s in &manifest.signatures {
if self.trusted_keys.read().contains(&s.key_id) {
has_trusted = true;
} else {

if s.sig.len() < 8 {
res.warnings.push(format!("signature from {} suspicious/too short", s.key_id));
}
}
}
if !has_trusted {
res.warnings.push("no signature from trusted key found".to_string());
}
}


if let Some(sbom) = &manifest.sbom {
if sbom.license.is_none() {
res.warnings.push("sbom present but license not specified".to_string());
}
} else {

res.warnings.push("no SBOM included; cannot fully verify supply-chain".to_string());
}

Ok(res)
}
}


fn is_valid_sha256_hex(s: &str) -> bool {
if s.len() != 64 {
return false;
}

match Vec::from_hex(s) {
Ok(_) => { true },
Err(_) => { false },
}
}

#[cfg(test)]
mod tests {
use super::*;

#[allow(dead_code)]
fn sample_manifest_ok() -> Manifest {

let sbom_data = SBOM {
name: Some("demo".to_string()),
license: Some("MIT".to_string()),
supplier: None,
extra: HashMap::new(),
};
Manifest {
name: "demo".to_string(),
version: Some("0.1".to_string()),
entrypoint: "a3b1f9b0c8d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d".to_string(),
blobs: vec![],
signatures: vec![Signature { key_id: "trusted-key".to_string(), sig: "signed".to_string() }],
sbom: Some(sbom_data),
meta: HashMap::new(),
}
}

#[test]
fn test_is_valid_sha256() {

let valid = "3cca5fcf71bf8609a64c354abf4773110dd315159be317b4218b7b8fadb6d0ce";
assert!(is_valid_sha256_hex(valid));
assert!(!is_valid_sha256_hex("xyz"));
}

#[test]
fn test_banned_hash_rejected() {
let val = Validator::new();
let banned = "3cca5fcf71bf8609a64c354abf4773110dd315159be317b4218b7b8fadb6d0ce".to_string();
val.ban_hash(&banned);

let manifest = Manifest {
name: "evil".to_string(),
version: None,
entrypoint: banned.clone(),
blobs: vec![BlobRef { hash: banned.clone(), r#type: "wasm".to_string() }],
signatures: vec![],
sbom: None,
meta: HashMap::new(),
};

let mut res = val.validate_manifest(&manifest).expect("validate");
assert!(!res.ok);
assert!(res.errors.iter().any(|e| e.contains("banned")));
}

#[test]
fn test_valid_manifest_passes_basic_checks() {
let val = Validator::new();

let valid = "3cca5fcf71bf8609a64c354abf4773110dd315159be317b4218b7b8fadb6d0ce".to_string();


let sbom_data = SBOM {
name: Some("p".into()),
license: Some("Apache-2.0".to_string()),
supplier: None,
extra: HashMap::new(),
};

let manifest = Manifest {
name: "good".to_string(),
version: Some("0.1".to_string()),
entrypoint: valid.clone(),
blobs: vec![BlobRef { hash: valid.clone(), r#type: "wasm".to_string() }],
signatures: vec![Signature { key_id: "trusted-key".to_string(), sig: "sig".to_string() }],
sbom: Some(sbom_data),
meta: HashMap::new(),
};
let mut res = val.validate_manifest(&manifest).expect("validate");

assert!(res.ok);
assert!(res.errors.is_empty());
}
}