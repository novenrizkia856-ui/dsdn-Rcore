






use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use futures::Stream;
use parking_lot::RwLock;










#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlobRef {

pub height: u64,

pub commitment: [u8; 32],

pub namespace: [u8; 29],
}






#[derive(Debug, Clone)]
pub struct Blob {

pub ref_: BlobRef,

pub data: Vec<u8>,

pub received_at: u64,
}









#[derive(Debug)]
pub struct DAMetrics {

pub post_count: AtomicU64,

pub get_count: AtomicU64,

pub subscribe_count: AtomicU64,

pub health_check_count: AtomicU64,

pub post_latency_us: AtomicU64,

pub get_latency_us: AtomicU64,

pub error_count: AtomicU64,

pub retry_count: AtomicU64,

pub reconnect_count: AtomicU64,

pub last_operation_ms: AtomicU64,
}

impl DAMetrics {

pub fn new() -> Self {
Self {
post_count: AtomicU64::new(0),
get_count: AtomicU64::new(0),
subscribe_count: AtomicU64::new(0),
health_check_count: AtomicU64::new(0),
post_latency_us: AtomicU64::new(0),
get_latency_us: AtomicU64::new(0),
error_count: AtomicU64::new(0),
retry_count: AtomicU64::new(0),
reconnect_count: AtomicU64::new(0),
last_operation_ms: AtomicU64::new(0),
}
}


pub fn record_post(&self, latency: std::time::Duration) {
self.post_count.fetch_add(1, Ordering::Relaxed);
self.post_latency_us.fetch_add(latency.as_micros() as u64, Ordering::Relaxed);
self.update_last_operation();
}


pub fn record_get(&self, latency: std::time::Duration) {
self.get_count.fetch_add(1, Ordering::Relaxed);
self.get_latency_us.fetch_add(latency.as_micros() as u64, Ordering::Relaxed);
self.update_last_operation();
}


pub fn record_error(&self) {
self.error_count.fetch_add(1, Ordering::Relaxed);
}


pub fn record_retry(&self) {
self.retry_count.fetch_add(1, Ordering::Relaxed);
}


pub fn record_reconnect(&self) {
self.reconnect_count.fetch_add(1, Ordering::Relaxed);
}


pub fn record_health_check(&self) {
self.health_check_count.fetch_add(1, Ordering::Relaxed);
self.update_last_operation();
}


pub fn record_subscribe(&self) {
self.subscribe_count.fetch_add(1, Ordering::Relaxed);
self.update_last_operation();
}


fn update_last_operation(&self) {
let now = std::time::SystemTime::now()
.duration_since(std::time::UNIX_EPOCH)
.map(|d| d.as_millis() as u64)
.unwrap_or(0);
self.last_operation_ms.store(now, Ordering::Relaxed);
}



pub fn avg_post_latency_us(&self) -> u64 {
let count = self.post_count.load(Ordering::Relaxed);
if count == 0 {
return 0;
}
self.post_latency_us.load(Ordering::Relaxed) / count
}



pub fn avg_get_latency_us(&self) -> u64 {
let count = self.get_count.load(Ordering::Relaxed);
if count == 0 {
return 0;
}
self.get_latency_us.load(Ordering::Relaxed) / count
}


pub fn snapshot(&self) -> DAMetricsSnapshot {
DAMetricsSnapshot {
post_count: self.post_count.load(Ordering::Relaxed),
get_count: self.get_count.load(Ordering::Relaxed),
subscribe_count: self.subscribe_count.load(Ordering::Relaxed),
health_check_count: self.health_check_count.load(Ordering::Relaxed),
avg_post_latency_us: self.avg_post_latency_us(),
avg_get_latency_us: self.avg_get_latency_us(),
error_count: self.error_count.load(Ordering::Relaxed),
retry_count: self.retry_count.load(Ordering::Relaxed),
reconnect_count: self.reconnect_count.load(Ordering::Relaxed),
last_operation_ms: self.last_operation_ms.load(Ordering::Relaxed),
}
}
}

impl Default for DAMetrics {
fn default() -> Self {
Self::new()
}
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DAMetricsSnapshot {
pub post_count: u64,
pub get_count: u64,
pub subscribe_count: u64,
pub health_check_count: u64,
pub avg_post_latency_us: u64,
pub avg_get_latency_us: u64,
pub error_count: u64,
pub retry_count: u64,
pub reconnect_count: u64,
pub last_operation_ms: u64,
}









#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DAConfig {

pub rpc_url: String,

pub namespace: [u8; 29],

pub auth_token: Option<String>,

pub timeout_ms: u64,

pub retry_count: u8,

pub retry_delay_ms: u64,

pub network: String,

pub enable_pooling: bool,

pub max_connections: u16,

pub idle_timeout_ms: u64,
}

impl Default for DAConfig {
















fn default() -> Self {
Self {
rpc_url: "http://localhost:26658".to_string(),
namespace: [0u8; 29],
auth_token: None,
timeout_ms: 30000,
retry_count: 3,
retry_delay_ms: 1000,
network: "local".to_string(),
enable_pooling: true,
max_connections: 10,
idle_timeout_ms: 60000,
}
}
}

impl DAConfig {


























pub fn from_env() -> Result<Self, DAError> {

let rpc_url = std::env::var("DA_RPC_URL")
.map_err(|_| DAError::Other("DA_RPC_URL environment variable not set".to_string()))?;


let namespace_hex = std::env::var("DA_NAMESPACE")
.map_err(|_| DAError::Other("DA_NAMESPACE environment variable not set".to_string()))?;

let mut namespace = Self::parse_namespace(&namespace_hex)?;


let auth_token = std::env::var("DA_AUTH_TOKEN").ok();


let timeout_ms = match std::env::var("DA_TIMEOUT_MS") {
Ok(val) => {
val.parse::<u64>().map_err(|_| {
DAError::Other(format!("DA_TIMEOUT_MS invalid: '{}'", val))
})?
},
Err(_) => { 30000 },
};


let retry_count = match std::env::var("DA_RETRY_COUNT") {
Ok(val) => {
val.parse::<u8>().map_err(|_| {
DAError::Other(format!("DA_RETRY_COUNT invalid: '{}'", val))
})?
},
Err(_) => { 3 },
};


let retry_delay_ms = match std::env::var("DA_RETRY_DELAY_MS") {
Ok(val) => {
val.parse::<u64>().map_err(|_| {
DAError::Other(format!("DA_RETRY_DELAY_MS invalid: '{}'", val))
})?
},
Err(_) => { 1000 },
};


let network = std::env::var("DA_NETWORK").unwrap_or_else(|_| "mainnet".to_string());


if network == "mainnet" && auth_token.is_none() {
return Err(DAError::Other(
"DA_AUTH_TOKEN is required for mainnet network".to_string()
))
}


let enable_pooling = match std::env::var("DA_ENABLE_POOLING") {
Ok(val) => { val.to_lowercase() == "true" || val == "1" },
Err(_) => { true },
};


let max_connections = match std::env::var("DA_MAX_CONNECTIONS") {
Ok(val) => {
val.parse::<u16>().map_err(|_| {
DAError::Other(format!("DA_MAX_CONNECTIONS invalid: '{}'", val))
})?
},
Err(_) => { 10 },
};


let idle_timeout_ms = match std::env::var("DA_IDLE_TIMEOUT_MS") {
Ok(val) => {
val.parse::<u64>().map_err(|_| {
DAError::Other(format!("DA_IDLE_TIMEOUT_MS invalid: '{}'", val))
})?
},
Err(_) => { 60000 },
};

Ok(Self {
rpc_url: rpc_url,
namespace: namespace,
auth_token: auth_token,
timeout_ms: timeout_ms,
retry_count: retry_count,
retry_delay_ms: retry_delay_ms,
network: network,
enable_pooling: enable_pooling,
max_connections: max_connections,
idle_timeout_ms: idle_timeout_ms,
})
}


pub fn is_mainnet(&self) -> bool {
self.network == "mainnet"
}



















pub fn validate_for_production(&self) -> Result<(), DAError> {
if self.is_mainnet() {


if self.auth_token.is_none() {
return Err(DAError::Other(
"auth_token is required for mainnet (needed for light node RPC auth)".to_string()
))
}






}
Ok(())
}











fn parse_namespace(hex: &str) -> Result<[u8; 29], DAError> {

if hex.len() != 58 {
return Err(DAError::Other(format!(
"DA_NAMESPACE must be 58 hex characters (29 bytes), got {} characters",
hex.len()
)))
}

let mut bytes = Self::hex_to_bytes(hex).map_err(|e| {
DAError::Other(format!("DA_NAMESPACE invalid hex: {}", e))
})?;

let mut namespace = [0u8; 29];
namespace.copy_from_slice(&bytes);
Ok(namespace)
}


fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
if hex.len() % 2 != 0 {
return Err("hex string must have even length".to_string());
}

let mut bytes = Vec::with_capacity(hex.len() / 2);
for i in (0..hex.len()).step_by(2) {
let byte_str = &hex[i..i + 2];
let byte = u8::from_str_radix(byte_str, 16)
.map_err(|_| format!("invalid hex byte: '{}'", byte_str))?;
bytes.push(byte);
}
Ok(bytes)
}
}




#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DAHealthStatus {

Healthy,

Degraded,

Unavailable,
}





#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DAError {


BlobNotFound(BlobRef),




InvalidBlob,


InvalidNamespace,



SerializationError(String),



NetworkError(String),


Timeout,


Unavailable,


AuthError(String),


Other(String),
}

impl std::fmt::Display for DAError {
fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
match self {
DAError::BlobNotFound(r) => { write!(f, "blob not found at height {}", r.height) },
DAError::InvalidBlob => { write!(f, "invalid blob data") },
DAError::InvalidNamespace => { write!(f, "invalid namespace") },
DAError::SerializationError(msg) => { write!(f, "serialization error: {}", msg) },
DAError::NetworkError(msg) => { write!(f, "network error: {}", msg) },
DAError::Timeout => { write!(f, "operation timeout") },
DAError::Unavailable => { write!(f, "DA layer unavailable") },
DAError::AuthError(msg) => { write!(f, "auth error: {}", msg) },
DAError::Other(msg) => { write!(f, "{}", msg) },
}
}
}

impl std::error::Error for DAError {}






pub type BlobStream = Pin<Box<dyn Stream<Item = Result<Blob, DAError>> + Send>>;


pub type BlobFuture = Pin<Box<dyn Future<Output = Result<Vec<u8>, DAError>> + Send>>;





































pub trait DALayer: Send + Sync {










fn post_blob(&self, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<BlobRef, DAError>> + Send + '_>>;











fn get_blob(&self, ref_: &BlobRef) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DAError>> + Send + '_>>;











fn subscribe_blobs(&self, from_height: Option<u64>) -> Pin<Box<dyn Future<Output = Result<BlobStream, DAError>> + Send + '_>>;







fn health_check(&self) -> Pin<Box<dyn Future<Output = Result<DAHealthStatus, DAError>> + Send + '_>>;




fn metrics(&self) -> Option<DAMetricsSnapshot> {
None
}
}





#[cfg(test)]
mod tests {
use super::*;










use std::sync::Mutex;



static ENV_MUTEX: Mutex<()> = Mutex::new(());


const DA_ENV_VARS: &[&str] = &[
"DA_RPC_URL",
"DA_NAMESPACE",
"DA_AUTH_TOKEN",
"DA_NETWORK",
"DA_TIMEOUT_MS",
"DA_RETRY_COUNT",
"DA_RETRY_DELAY_MS",
"DA_ENABLE_POOLING",
"DA_MAX_CONNECTIONS",
"DA_IDLE_TIMEOUT_MS",
];


















struct EnvGuard {
_lock: std::sync::MutexGuard<'static, ()>,
original_values: Vec<(&'static str, Option<String>)>,
}

impl EnvGuard {

fn new() -> Self {

let lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());


let original_values: Vec<_> = DA_ENV_VARS
.iter()
.map(|&var| (var, std::env::var(var).ok()))
.collect();

Self {
_lock: lock,
original_values: original_values,
}
}
}

impl Drop for EnvGuard {
fn drop(&mut self) {

for (var, original) in &self.original_values {
match original {
Some(value) => { std::env::set_var(var, value) },
None => { std::env::remove_var(var) },
}
}
}
}





#[test]
fn test_blobref_creation() {
let blob_ref = BlobRef {
height: 100,
commitment: [0xAB; 32],
namespace: [0xCD; 29],
};

assert_eq!(blob_ref.height, 100);
assert_eq!(blob_ref.commitment, [0xAB; 32]);
assert_eq!(blob_ref.namespace, [0xCD; 29]);
}

#[test]
fn test_blobref_clone_and_eq() {
let blob_ref1 = BlobRef {
height: 42,
commitment: [0x11; 32],
namespace: [0x22; 29],
};

let blob_ref2 = blob_ref1.clone();

assert_eq!(blob_ref1, blob_ref2);
}





#[test]
fn test_dametrics_new() {
let metrics = DAMetrics::new();

assert_eq!(metrics.post_count.load(Ordering::Relaxed), 0);
assert_eq!(metrics.get_count.load(Ordering::Relaxed), 0);
assert_eq!(metrics.error_count.load(Ordering::Relaxed), 0);
}

#[test]
fn test_dametrics_record_post() {
let metrics = DAMetrics::new();

metrics.record_post(std::time::Duration::from_millis(100));

assert_eq!(metrics.post_count.load(Ordering::Relaxed), 1);
assert!(metrics.post_latency_us.load(Ordering::Relaxed) >= 100_000);
}

#[test]
fn test_dametrics_record_get() {
let metrics = DAMetrics::new();

metrics.record_get(std::time::Duration::from_millis(50));

assert_eq!(metrics.get_count.load(Ordering::Relaxed), 1);
assert!(metrics.get_latency_us.load(Ordering::Relaxed) >= 50_000);
}

#[test]
fn test_dametrics_avg_latency() {
let metrics = DAMetrics::new();


metrics.record_post(std::time::Duration::from_millis(100));
metrics.record_post(std::time::Duration::from_millis(200));

let avg = metrics.avg_post_latency_us();
assert!(avg >= 150_000);
}

#[test]
fn test_dametrics_avg_latency_no_ops() {
let metrics = DAMetrics::new();

assert_eq!(metrics.avg_post_latency_us(), 0);
assert_eq!(metrics.avg_get_latency_us(), 0);
}

#[test]
fn test_dametrics_snapshot() {
let metrics = DAMetrics::new();

metrics.record_post(std::time::Duration::from_millis(100));
metrics.record_error();
metrics.record_retry();

let snapshot = metrics.snapshot();

assert_eq!(snapshot.post_count, 1);
assert_eq!(snapshot.error_count, 1);
assert_eq!(snapshot.retry_count, 1);
}





#[test]
fn test_daconfig_default() {
let config = DAConfig::default();

assert_eq!(config.rpc_url, "http://localhost:26658");
assert_eq!(config.namespace, [0u8; 29]);
assert!(config.auth_token.is_none());
assert_eq!(config.timeout_ms, 30000);
assert_eq!(config.retry_count, 3);
assert_eq!(config.retry_delay_ms, 1000);
assert_eq!(config.network, "local");
assert!(config.enable_pooling);
}

#[test]
fn test_daconfig_from_env_missing_rpc_url() {
let _guard = EnvGuard::new();
std::env::remove_var("DA_RPC_URL");
std::env::remove_var("DA_NAMESPACE");

let result = DAConfig::from_env();
assert!(result.is_err());
}

#[test]
fn test_daconfig_from_env_missing_namespace() {
let _guard = EnvGuard::new();
std::env::set_var("DA_RPC_URL", "http://test:1234");
std::env::remove_var("DA_NAMESPACE");

let result = DAConfig::from_env();
assert!(result.is_err());

}

#[test]
fn test_daconfig_from_env_invalid_namespace_length() {
let _guard = EnvGuard::new();
std::env::set_var("DA_RPC_URL", "http://test:1234");
std::env::set_var("DA_NAMESPACE", "0011223344");

let result = DAConfig::from_env();
assert!(result.is_err());

let err = result.unwrap_err();
if let DAError::Other(msg) = err {
assert!(msg.contains("58 hex characters"));
} else {
panic!("Expected DAError::Other");
}

}

#[test]
fn test_daconfig_from_env_mainnet_requires_auth() {
let _guard = EnvGuard::new();
std::env::set_var("DA_RPC_URL", "http://celestia:26658");
std::env::set_var("DA_NAMESPACE", "00112233445566778899aabbccddeeff00112233445566778899aabbcc");
std::env::set_var("DA_NETWORK", "mainnet");
std::env::remove_var("DA_AUTH_TOKEN");

let result = DAConfig::from_env();
assert!(result.is_err());

let err = result.unwrap_err();
if let DAError::Other(msg) = err {
assert!(msg.contains("required for mainnet"));
} else {
panic!("Expected DAError::Other about auth token");
}

}

#[test]
fn test_daconfig_from_env_success_local() {
let _guard = EnvGuard::new();
std::env::set_var("DA_RPC_URL", "http://celestia:26658");
std::env::set_var("DA_NAMESPACE", "00112233445566778899aabbccddeeff00112233445566778899aabbcc");
std::env::set_var("DA_NETWORK", "local");
std::env::remove_var("DA_AUTH_TOKEN");

let result = DAConfig::from_env();
assert!(result.is_ok(), "from_env should succeed for local network without auth token");

let config = result.unwrap();
assert_eq!(config.network, "local");
assert!(config.auth_token.is_none());

}

#[test]
fn test_daconfig_from_env_success_mainnet() {
let _guard = EnvGuard::new();
std::env::set_var("DA_RPC_URL", "http://celestia:26658");
std::env::set_var("DA_NAMESPACE", "00112233445566778899aabbccddeeff00112233445566778899aabbcc");
std::env::set_var("DA_AUTH_TOKEN", "secret_token_123");
std::env::set_var("DA_NETWORK", "mainnet");

let result = DAConfig::from_env();
assert!(result.is_ok(), "from_env should succeed for mainnet with auth token");

let config = result.unwrap();
assert_eq!(config.rpc_url, "http://celestia:26658");
assert_eq!(config.auth_token, Some("secret_token_123".to_string()));
assert!(config.is_mainnet());

}

#[test]
fn test_daconfig_validate_for_production_mainnet_localhost_with_auth() {

let config = DAConfig {
rpc_url: "http://localhost:26658".to_string(),
namespace: [0u8; 29],
auth_token: Some("token".to_string()),
network: "mainnet".to_string(),
..Default::default()
};

let result = config.validate_for_production();
assert!(result.is_ok(), "localhost with auth_token should be valid for mainnet (light node setup)");
}

#[test]
fn test_daconfig_validate_for_production_mainnet_127_with_auth() {

let config = DAConfig {
rpc_url: "http://127.0.0.1:26658".to_string(),
namespace: [0u8; 29],
auth_token: Some("token".to_string()),
network: "mainnet".to_string(),
..Default::default()
};

let result = config.validate_for_production();
assert!(result.is_ok(), "127.0.0.1 with auth_token should be valid for mainnet (light node setup)");
}

#[test]
fn test_daconfig_validate_for_production_mainnet_no_auth() {
let config = DAConfig {
rpc_url: "http://celestia:26658".to_string(),
namespace: [0u8; 29],
auth_token: None,
network: "mainnet".to_string(),
..Default::default()
};

let result = config.validate_for_production();
assert!(result.is_err());
}





#[test]
fn test_daerror_display() {
let errors = vec!(
(DAError::InvalidBlob, "invalid blob data"),
(DAError::InvalidNamespace, "invalid namespace"),
(DAError::Timeout, "operation timeout"),
(DAError::Unavailable, "DA layer unavailable"),
(DAError::AuthError("bad token".to_string()), "auth error: bad token"),
(DAError::NetworkError("conn refused".to_string()), "network error: conn refused"),
);

for (err, expected) in errors {
assert!(err.to_string().contains(expected));
}
}





#[test]
fn test_blob_creation() {
let blob_ref = BlobRef {
height: 100,
commitment: [0x11; 32],
namespace: [0x22; 29],
};

let blob = Blob {
ref_: blob_ref.clone(),
data: vec!(1, 2, 3, 4, 5),
received_at: 1234567890,
};

assert_eq!(blob.ref_, blob_ref);
assert_eq!(blob.data, vec!(1, 2, 3, 4, 5));
assert_eq!(blob.received_at, 1234567890);
}
}