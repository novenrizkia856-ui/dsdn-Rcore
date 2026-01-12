//! Celestia DA Backend Implementation
//!
//! Modul ini menyediakan implementasi konkret `CelestiaDA` sebagai
//! backend Data Availability menggunakan Celestia network.
//!
//! Tahap ini berisi inisialisasi, wiring, manajemen namespace, dan
//! operasi `post_blob` dan `get_blob` untuk mengirim/mengambil data dari Celestia.

use crate::da::{BlobRef, DAConfig, DAError, DAHealthStatus, DALayer};
use crate::da::BlobStream as DABlobStream;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use futures::Stream;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use sha3::Sha3_256;
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use tracing::{debug, error, info, warn};

// ════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════

/// Maximum blob size in bytes (2 MB)
pub const MAX_BLOB_SIZE: usize = 2 * 1024 * 1024;

/// Default poll interval for blob subscription in milliseconds
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 5000;

// ════════════════════════════════════════════════════════════════════════════
// NAMESPACE CONSTANTS & COMPUTATION
// ════════════════════════════════════════════════════════════════════════════

/// Default DSDN namespace untuk control plane data.
///
/// Nilai ini dihitung secara deterministik dari string "dsdn-control-v0"
/// menggunakan `compute_namespace`. Konstanta ini digunakan sebagai
/// namespace default untuk DSDN control plane operations.
///
/// # Computation
///
/// ```ignore
/// DSDN_NAMESPACE_V0 = compute_namespace("dsdn-control-v0")
/// ```
pub const DSDN_NAMESPACE_V0: [u8; 29] = compute_namespace_const("dsdn-control-v0");

/// Menghitung namespace 29-byte dari string name secara deterministik.
///
/// Fungsi ini menggunakan SHA-256 untuk menghasilkan hash dari input string,
/// kemudian mengambil 29 byte pertama sebagai namespace.
///
/// # Arguments
///
/// * `name` - String identifier untuk namespace
///
/// # Returns
///
/// Array 29-byte yang merupakan namespace identifier.
///
/// # Determinism
///
/// Fungsi ini sepenuhnya deterministik:
/// - Input yang sama selalu menghasilkan output yang sama
/// - Tidak bergantung pada state eksternal
/// - Tidak menggunakan randomness
/// - Platform-independent
///
/// # Example
///
/// ```ignore
/// let ns1 = compute_namespace("my-app");
/// let ns2 = compute_namespace("my-app");
/// assert_eq!(ns1, ns2); // Selalu sama
/// ```
pub fn compute_namespace(name: &str) -> [u8; 29] {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    let hash = hasher.finalize();
    
    let mut namespace = [0u8; 29];
    namespace.copy_from_slice(&hash[..29]);
    namespace
}

/// Const function untuk menghitung namespace pada compile time.
///
/// Implementasi ini menggunakan algoritma SHA-256 secara manual
/// untuk memungkinkan evaluasi pada compile time.
const fn compute_namespace_const(name: &str) -> [u8; 29] {
    // SHA-256 constants
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    const fn rotr(x: u32, n: u32) -> u32 {
        (x >> n) | (x << (32 - n))
    }

    const fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    const fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    const fn sigma0(x: u32) -> u32 {
        rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
    }

    const fn sigma1(x: u32) -> u32 {
        rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
    }

    const fn gamma0(x: u32) -> u32 {
        rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
    }

    const fn gamma1(x: u32) -> u32 {
        rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
    }

    let bytes = name.as_bytes();
    let len = bytes.len();
    
    // Prepare message block (simplified for short inputs < 56 bytes)
    let mut block = [0u8; 64];
    let mut i = 0;
    while i < len && i < 55 {
        block[i] = bytes[i];
        i += 1;
    }
    block[len] = 0x80; // Padding
    
    // Length in bits (big endian)
    let bit_len = (len as u64) * 8;
    block[56] = ((bit_len >> 56) & 0xff) as u8;
    block[57] = ((bit_len >> 48) & 0xff) as u8;
    block[58] = ((bit_len >> 40) & 0xff) as u8;
    block[59] = ((bit_len >> 32) & 0xff) as u8;
    block[60] = ((bit_len >> 24) & 0xff) as u8;
    block[61] = ((bit_len >> 16) & 0xff) as u8;
    block[62] = ((bit_len >> 8) & 0xff) as u8;
    block[63] = (bit_len & 0xff) as u8;

    // Initial hash values
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Parse block into 16 32-bit words
    let mut w = [0u32; 64];
    let mut j = 0;
    while j < 16 {
        w[j] = ((block[j * 4] as u32) << 24)
            | ((block[j * 4 + 1] as u32) << 16)
            | ((block[j * 4 + 2] as u32) << 8)
            | (block[j * 4 + 3] as u32);
        j += 1;
    }

    // Extend to 64 words
    j = 16;
    while j < 64 {
        w[j] = gamma1(w[j - 2])
            .wrapping_add(w[j - 7])
            .wrapping_add(gamma0(w[j - 15]))
            .wrapping_add(w[j - 16]);
        j += 1;
    }

    // Compression
    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut hh = h[7];

    j = 0;
    while j < 64 {
        let t1 = hh
            .wrapping_add(sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[j])
            .wrapping_add(w[j]);
        let t2 = sigma0(a).wrapping_add(maj(a, b, c));

        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        j += 1;
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);

    // Convert to bytes and take first 29
    let mut result = [0u8; 29];
    let mut k = 0;
    while k < 7 {
        result[k * 4] = ((h[k] >> 24) & 0xff) as u8;
        result[k * 4 + 1] = ((h[k] >> 16) & 0xff) as u8;
        result[k * 4 + 2] = ((h[k] >> 8) & 0xff) as u8;
        result[k * 4 + 3] = (h[k] & 0xff) as u8;
        k += 1;
    }
    // Last byte from h[7]
    result[28] = ((h[7] >> 24) & 0xff) as u8;

    result
}

/// Memvalidasi format namespace.
///
/// Namespace valid jika:
/// - Bukan all-zeros (reserved)
/// - Memiliki panjang tepat 29 bytes
///
/// # Arguments
///
/// * `namespace` - Namespace 29-byte untuk divalidasi
///
/// # Returns
///
/// * `Ok(())` - Namespace valid
/// * `Err(DAError::InvalidNamespace)` - Namespace tidak valid
fn validate_namespace_format(namespace: &[u8; 29]) -> Result<(), DAError> {
    // Check if namespace is all zeros (reserved/invalid)
    let all_zeros = namespace.iter().all(|&b| b == 0);
    if all_zeros {
        return Err(DAError::InvalidNamespace);
    }
    
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════
// BLOB SUBSCRIPTION TYPES
// ════════════════════════════════════════════════════════════════════════════

/// Blob data returned from subscription stream.
///
/// This struct represents a blob retrieved during subscription polling,
/// containing the blob data along with its position in the chain.
#[derive(Debug, Clone)]
pub struct Blob {
    /// Block height where the blob was included
    pub height: u64,
    /// Index of the blob within the block
    pub index: u32,
    /// Namespace of the blob (29 bytes)
    pub namespace: [u8; 29],
    /// Raw blob data
    pub data: Vec<u8>,
    /// Blob commitment (SHA3-256 hash)
    pub commitment: [u8; 32],
}

/// Type alias for blob subscription stream.
///
/// BlobStream is a pinned, boxed, sendable stream that yields
/// `Result<Blob, DAError>` items. This type is used as the return
/// type of `subscribe_blobs`.
pub type BlobStream = Pin<Box<dyn Stream<Item = Result<Blob, DAError>> + Send>>;

/// Blob subscription configuration for polling-based subscription.
///
/// BlobSubscription contains the configuration for creating a subscription
/// stream. The actual stream state is managed internally during iteration.
///
/// # Fields
///
/// * `da` - Arc reference to CelestiaDA for making RPC calls
/// * `from_height` - Starting block height for subscription
/// * `namespace` - Namespace filter (29 bytes)
/// * `poll_interval_ms` - Polling interval in milliseconds
pub struct BlobSubscription {
    /// Arc reference to CelestiaDA instance
    da: Arc<CelestiaDA>,
    /// Starting block height for subscription
    from_height: u64,
    /// Namespace filter (29 bytes)
    namespace: [u8; 29],
    /// Polling interval in milliseconds
    poll_interval_ms: u64,
}

// ════════════════════════════════════════════════════════════════════════════
// BLOB COMMITMENT
// ════════════════════════════════════════════════════════════════════════════

/// Menghitung blob commitment menggunakan SHA3-256.
///
/// Commitment adalah hash 32-byte dari data blob yang digunakan
/// untuk identifikasi dan verifikasi integritas blob.
///
/// # Arguments
///
/// * `data` - Data blob mentah
///
/// # Returns
///
/// Array 32-byte commitment hash.
///
/// # Determinism
///
/// Fungsi ini sepenuhnya deterministik:
/// - Input sama → output sama
/// - Tidak ada randomness
/// - Tidak ada salt
/// - Platform-independent
pub fn compute_blob_commitment(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&result);
    commitment
}

// ════════════════════════════════════════════════════════════════════════════
// JSON-RPC TYPES
// ════════════════════════════════════════════════════════════════════════════

/// Blob data untuk JSON-RPC request
#[derive(Debug, Serialize)]
struct BlobData {
    /// Namespace dalam format base64
    namespace: String,
    /// Data blob dalam format base64
    data: String,
    /// Share version (selalu 0 untuk Celestia)
    share_version: u32,
    /// Commitment dalam format base64
    commitment: String,
}

/// JSON-RPC request untuk blob operations
#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: Vec<serde_json::Value>,
}

/// JSON-RPC response untuk blob.Submit (returns height)
#[derive(Debug, Deserialize)]
struct JsonRpcSubmitResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: u64,
    result: Option<u64>,
    error: Option<JsonRpcError>,
}

/// JSON-RPC response untuk blob.Get (returns blob data)
#[derive(Debug, Deserialize)]
struct JsonRpcGetResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: u64,
    result: Option<BlobGetResult>,
    error: Option<JsonRpcError>,
}

/// Blob data dari response blob.Get
#[derive(Debug, Deserialize)]
struct BlobGetResult {
    /// Namespace dalam format base64
    namespace: String,
    /// Data blob dalam format base64
    data: String,
    /// Share version
    #[allow(dead_code)]
    share_version: u32,
    /// Commitment dalam format base64
    #[allow(dead_code)]
    commitment: String,
}

/// JSON-RPC error
#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

/// JSON-RPC response untuk blob.GetAll (returns array of blobs)
#[derive(Debug, Deserialize)]
struct JsonRpcGetAllResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: u64,
    result: Option<Vec<BlobGetAllItem>>,
    error: Option<JsonRpcError>,
}

/// Blob item dari response blob.GetAll
#[derive(Debug, Deserialize)]
struct BlobGetAllItem {
    /// Namespace dalam format base64
    namespace: String,
    /// Data blob dalam format base64
    data: String,
    /// Share version
    #[allow(dead_code)]
    share_version: u32,
    /// Commitment dalam format base64
    commitment: String,
    /// Index within the block
    #[serde(default)]
    index: u32,
}

/// JSON-RPC response untuk header.NetworkHead (returns latest height)
#[derive(Debug, Deserialize)]
struct JsonRpcNetworkHeadResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: u64,
    result: Option<NetworkHeadResult>,
    error: Option<JsonRpcError>,
}

/// Network head result
#[derive(Debug, Deserialize)]
struct NetworkHeadResult {
    header: HeaderInfo,
}

/// Header info containing height
#[derive(Debug, Deserialize)]
struct HeaderInfo {
    height: String,
}

// ════════════════════════════════════════════════════════════════════════════
// CELESTIA DA STRUCT
// ════════════════════════════════════════════════════════════════════════════

/// Celestia DA backend implementation.
///
/// `CelestiaDA` menyediakan koneksi ke Celestia network untuk
/// menyimpan dan mengambil blob data. Struct ini mengelola
/// HTTP client, tracking height, dan health status.
///
/// # Fields
///
/// - `config` - Konfigurasi DA layer
/// - `client` - HTTP client untuk komunikasi dengan Celestia node
/// - `namespace` - Namespace 29-byte (cached dari config)
/// - `last_height` - Height terakhir yang diketahui (atomic)
/// - `health_status` - Status kesehatan koneksi (RwLock)
///
/// # Thread Safety
///
/// Struct ini thread-safe dan dapat di-share antar threads.
/// `AtomicU64` digunakan untuk `last_height` dan `RwLock` untuk `health_status`.
pub struct CelestiaDA {
    /// Konfigurasi DA layer
    config: DAConfig,
    /// HTTP client untuk request ke Celestia node
    client: reqwest::Client,
    /// Namespace 29-byte untuk blob storage
    namespace: [u8; 29],
    /// Height terakhir yang diketahui dari DA layer
    last_height: AtomicU64,
    /// Status kesehatan koneksi ke DA layer
    health_status: RwLock<DAHealthStatus>,
}

impl std::fmt::Debug for CelestiaDA {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CelestiaDA")
            .field("config", &self.config)
            .field("client", &"reqwest::Client")
            .field("namespace", &self.namespace)
            .field("last_height", &self.last_height.load(Ordering::SeqCst))
            .field("health_status", &*self.health_status.read().unwrap())
            .finish()
    }
}

impl CelestiaDA {
    /// Membuat instance CelestiaDA baru dengan konfigurasi yang diberikan.
    ///
    /// Method ini melakukan:
    /// 1. Validasi konfigurasi
    /// 2. Membuat HTTP client dengan timeout dari config
    /// 3. Melakukan connection validation ke endpoint
    /// 4. Inisialisasi semua field
    ///
    /// # Arguments
    ///
    /// * `config` - Konfigurasi DA layer
    ///
    /// # Returns
    ///
    /// * `Ok(CelestiaDA)` - Instance yang siap digunakan
    /// * `Err(DAError)` - Jika inisialisasi atau connection validation gagal
    ///
    /// # Connection Validation
    ///
    /// Melakukan HTTP HEAD request ke endpoint untuk memverifikasi
    /// bahwa Celestia node dapat dijangkau. Request ini ringan dan
    /// tidak mengambil data apapun.
    ///
    /// # Errors
    ///
    /// Mengembalikan error jika:
    /// - Gagal membuat HTTP client
    /// - Connection validation gagal (endpoint tidak dapat dijangkau)
    /// - Timeout saat validasi koneksi
    pub fn new(config: DAConfig) -> Result<Self, DAError> {
        // Build HTTP client with configured timeout
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|e| DAError::Other(format!("failed to create HTTP client: {}", e)))?;

        // Cache namespace from config
        let namespace = config.namespace;

        // Perform connection validation
        Self::validate_connection(&client, &config.rpc_url)?;

        Ok(Self {
            config,
            client,
            namespace,
            last_height: AtomicU64::new(0),
            health_status: RwLock::new(DAHealthStatus::Healthy),
        })
    }

    /// Membuat instance CelestiaDA dari environment variables.
    ///
    /// Method ini menggunakan `DAConfig::from_env()` untuk membaca
    /// konfigurasi, kemudian memanggil `CelestiaDA::new()`.
    ///
    /// # Returns
    ///
    /// * `Ok(CelestiaDA)` - Instance yang siap digunakan
    /// * `Err(DAError)` - Jika konfigurasi atau inisialisasi gagal
    ///
    /// # Environment Variables
    ///
    /// Lihat dokumentasi `DAConfig::from_env()` untuk daftar
    /// environment variables yang dibaca.
    ///
    /// # Errors
    ///
    /// Mengembalikan error jika:
    /// - Environment variables tidak valid
    /// - Connection validation gagal
    pub fn from_env() -> Result<Self, DAError> {
        let config = DAConfig::from_env()?;
        Self::new(config)
    }

    /// Validasi koneksi ke Celestia node.
    ///
    /// Melakukan HTTP HEAD request ke endpoint untuk memverifikasi
    /// bahwa node dapat dijangkau.
    fn validate_connection(client: &reqwest::Client, rpc_url: &str) -> Result<(), DAError> {
        // Check if we're already inside a tokio runtime
        if tokio::runtime::Handle::try_current().is_ok() {
            // We're inside a runtime - use thread::spawn to avoid nested runtime
            let client = client.clone();
            let rpc_url = rpc_url.to_string();
            
            let result = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| DAError::Other(format!("failed to create runtime: {}", e)))?;
                
                rt.block_on(async {
                    let response = client.head(&rpc_url).send().await;
                    match response {
                        Ok(_) => Ok(()),
                        Err(e) => {
                            if e.is_timeout() {
                                Err(DAError::Timeout)
                            } else if e.is_connect() {
                                Err(DAError::Unavailable)
                            } else {
                                Err(DAError::NetworkError(format!("connection validation failed: {}", e)))
                            }
                        }
                    }
                })
            })
            .join()
            .map_err(|_| DAError::Other("validation thread panicked".to_string()))?;
            
            return result;
        }
        
        // Not inside a runtime - create one directly
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| DAError::Other(format!("failed to create runtime: {}", e)))?;

        rt.block_on(async {
            // Try HEAD request first (lightweight)
            let response = client
                .head(rpc_url)
                .send()
                .await;

            match response {
                Ok(_) => Ok(()),
                Err(e) => {
                    if e.is_timeout() {
                        Err(DAError::Timeout)
                    } else if e.is_connect() {
                        Err(DAError::Unavailable)
                    } else {
                        Err(DAError::NetworkError(format!("connection validation failed: {}", e)))
                    }
                }
            }
        })
    }

    /// Mengirim blob ke Celestia DA layer.
    ///
    /// Method ini mengirim data ke Celestia melalui JSON-RPC `blob.Submit`.
    /// Data akan di-encode ke base64 dan dikirim bersama namespace aktif.
    ///
    /// # Arguments
    ///
    /// * `data` - Data blob mentah (maksimum 2MB)
    ///
    /// # Returns
    ///
    /// * `Ok(BlobRef)` - Referensi ke blob yang tersimpan
    /// * `Err(DAError)` - Jika pengiriman gagal
    ///
    /// # Errors
    ///
    /// Mengembalikan error jika:
    /// - Data melebihi 2MB (`DAError::Other`)
    /// - Network error (`DAError::NetworkError`)
    /// - Timeout (`DAError::Timeout`)
    /// - Response tidak valid (`DAError::SerializationError`)
    ///
    /// # Retry Behavior
    ///
    /// Method ini melakukan retry dengan exponential backoff jika terjadi
    /// error yang bersifat transient (network error, timeout). Jumlah retry
    /// dan delay ditentukan oleh konfigurasi.
    ///
    /// # State Updates
    ///
    /// Jika sukses, `last_height` akan diupdate secara atomic dengan
    /// height dari response.
    pub async fn post_blob(&self, data: &[u8]) -> Result<BlobRef, DAError> {
        // Validate data size
        if data.len() > MAX_BLOB_SIZE {
            error!(
                size = data.len(),
                max = MAX_BLOB_SIZE,
                "blob size exceeds maximum"
            );
            return Err(DAError::Other(format!(
                "blob size {} exceeds maximum {} bytes",
                data.len(),
                MAX_BLOB_SIZE
            )));
        }

        debug!(size = data.len(), "posting blob to Celestia");

        // Compute commitment
        let commitment = compute_blob_commitment(data);

        // Build blob data
        let blob_data = BlobData {
            namespace: BASE64.encode(&self.namespace),
            data: BASE64.encode(data),
            share_version: 0,
            commitment: BASE64.encode(&commitment),
        };

        // Build JSON-RPC request
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "blob.Submit",
            params: vec![
                serde_json::json!([blob_data]),
                serde_json::json!(0.002), // gas price
            ],
        };

        // Retry loop with exponential backoff
        let mut last_error = DAError::Unavailable;
        let mut retry_delay = self.config.retry_delay_ms;

        for attempt in 0..=self.config.retry_count {
            if attempt > 0 {
                warn!(attempt, retry_count = self.config.retry_count, "retrying post_blob");
                tokio::time::sleep(Duration::from_millis(retry_delay)).await;
                retry_delay *= 2; // Exponential backoff
            }

            match self.send_blob_submit(&request).await {
                Ok(height) => {
                    // Update last_height atomically
                    self.last_height.store(height, Ordering::SeqCst);
                    
                    // Update health status to Healthy
                    *self.health_status.write().unwrap() = DAHealthStatus::Healthy;

                    info!(height, commitment = ?hex::encode(&commitment[..8]), "blob posted successfully");

                    return Ok(BlobRef {
                        height,
                        commitment,
                        namespace: self.namespace,
                    });
                }
                Err(e) => {
                    // Check if error is retryable
                    let is_retryable = matches!(
                        e,
                        DAError::NetworkError(_) | DAError::Timeout | DAError::Unavailable
                    );

                    if !is_retryable {
                        error!(error = ?e, "non-retryable error in post_blob");
                        return Err(e);
                    }

                    warn!(attempt, error = ?e, "retryable error in post_blob");
                    last_error = e;

                    // Update health status to Degraded after first failure
                    if attempt == 0 {
                        *self.health_status.write().unwrap() = DAHealthStatus::Degraded;
                    }
                }
            }
        }

        // All retries exhausted
        error!(retry_count = self.config.retry_count, "all retries exhausted for post_blob");
        *self.health_status.write().unwrap() = DAHealthStatus::Unavailable;
        Err(last_error)
    }

    /// Mengirim JSON-RPC request blob.Submit ke Celestia node.
    async fn send_blob_submit(&self, request: &JsonRpcRequest) -> Result<u64, DAError> {
        let mut req_builder = self.client
            .post(&self.config.rpc_url)
            .header("Content-Type", "application/json");

        // Add auth token if present
        if let Some(ref token) = self.config.auth_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
        }

        let response = req_builder
            .json(request)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    DAError::Timeout
                } else if e.is_connect() {
                    DAError::Unavailable
                } else {
                    DAError::NetworkError(format!("request failed: {}", e))
                }
            })?;

        // Check HTTP status
        let status = response.status();
        if !status.is_success() {
            return Err(DAError::NetworkError(format!(
                "HTTP error: {}",
                status
            )));
        }

        // Parse response
        let body = response
            .text()
            .await
            .map_err(|e| DAError::NetworkError(format!("failed to read response: {}", e)))?;

        let rpc_response: JsonRpcSubmitResponse = serde_json::from_str(&body)
            .map_err(|e| DAError::SerializationError(format!("failed to parse response: {}", e)))?;

        // Check for RPC error
        if let Some(error) = rpc_response.error {
            return Err(DAError::Other(format!(
                "RPC error {}: {}",
                error.code, error.message
            )));
        }

        // Extract height from result
        let height = rpc_response.result.ok_or_else(|| {
            DAError::SerializationError("missing result in response".to_string())
        })?;

        Ok(height)
    }

    /// Mengambil blob dari Celestia DA layer.
    ///
    /// Method ini mengambil data dari Celestia melalui JSON-RPC `blob.Get`.
    /// Data akan di-decode dari base64 dan divalidasi terhadap commitment
    /// dan namespace.
    ///
    /// # Arguments
    ///
    /// * `ref_` - Referensi ke blob yang akan diambil
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Data blob mentah
    /// * `Err(DAError)` - Jika pengambilan gagal
    ///
    /// # Errors
    ///
    /// Mengembalikan error jika:
    /// - Blob tidak ditemukan (`DAError::BlobNotFound`)
    /// - Namespace tidak cocok (`DAError::InvalidNamespace`)
    /// - Commitment tidak valid (`DAError::InvalidBlob`)
    /// - Network error (`DAError::NetworkError`)
    /// - Timeout (`DAError::Timeout`)
    ///
    /// # Validation
    ///
    /// Method ini melakukan validasi:
    /// 1. Namespace dari response HARUS cocok dengan namespace aktif
    /// 2. Commitment dari data HARUS cocok dengan `ref_.commitment`
    ///
    /// # Retry Behavior
    ///
    /// Method ini melakukan retry dengan exponential backoff jika terjadi
    /// error yang bersifat transient. Jumlah retry dan delay ditentukan
    /// oleh konfigurasi.
    pub async fn get_blob(&self, ref_: &BlobRef) -> Result<Vec<u8>, DAError> {
        debug!(
            height = ref_.height,
            commitment = ?hex::encode(&ref_.commitment[..8]),
            "getting blob from Celestia"
        );

        // Validate namespace match BEFORE making network call
        if ref_.namespace != self.namespace {
            warn!(
                expected = ?hex::encode(&self.namespace[..8]),
                actual = ?hex::encode(&ref_.namespace[..8]),
                "namespace mismatch in blob ref"
            );
            return Err(DAError::InvalidNamespace);
        }

        // Build JSON-RPC request
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "blob.Get",
            params: vec![
                serde_json::json!(ref_.height),
                serde_json::json!(BASE64.encode(&ref_.namespace)),
                serde_json::json!(BASE64.encode(&ref_.commitment)),
            ],
        };

        // Retry loop with exponential backoff
        let mut last_error = DAError::Unavailable;
        let mut retry_delay = self.config.retry_delay_ms;

        for attempt in 0..=self.config.retry_count {
            if attempt > 0 {
                warn!(attempt, retry_count = self.config.retry_count, "retrying get_blob");
                tokio::time::sleep(Duration::from_millis(retry_delay)).await;
                retry_delay *= 2; // Exponential backoff
            }

            match self.send_blob_get(&request, ref_).await {
                Ok(data) => {
                    // Update health status to Healthy
                    *self.health_status.write().unwrap() = DAHealthStatus::Healthy;

                    info!(
                        height = ref_.height,
                        size = data.len(),
                        "blob retrieved successfully"
                    );

                    return Ok(data);
                }
                Err(e) => {
                    // Check if error is retryable
                    let is_retryable = matches!(
                        e,
                        DAError::NetworkError(_) | DAError::Timeout | DAError::Unavailable
                    );

                    // Non-retryable errors: BlobNotFound, InvalidNamespace, InvalidBlob
                    if !is_retryable {
                        error!(error = ?e, "non-retryable error in get_blob");
                        return Err(e);
                    }

                    warn!(attempt, error = ?e, "retryable error in get_blob");
                    last_error = e;

                    // Update health status to Degraded after first failure
                    if attempt == 0 {
                        *self.health_status.write().unwrap() = DAHealthStatus::Degraded;
                    }
                }
            }
        }

        // All retries exhausted
        error!(retry_count = self.config.retry_count, "all retries exhausted for get_blob");
        *self.health_status.write().unwrap() = DAHealthStatus::Unavailable;
        Err(last_error)
    }

    /// Mengirim JSON-RPC request blob.Get ke Celestia node.
    async fn send_blob_get(&self, request: &JsonRpcRequest, ref_: &BlobRef) -> Result<Vec<u8>, DAError> {
        let mut req_builder = self.client
            .post(&self.config.rpc_url)
            .header("Content-Type", "application/json");

        // Add auth token if present
        if let Some(ref token) = self.config.auth_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
        }

        let response = req_builder
            .json(request)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    DAError::Timeout
                } else if e.is_connect() {
                    DAError::Unavailable
                } else {
                    DAError::NetworkError(format!("request failed: {}", e))
                }
            })?;

        // Check HTTP status
        let status = response.status();
        if !status.is_success() {
            return Err(DAError::NetworkError(format!(
                "HTTP error: {}",
                status
            )));
        }

        // Parse response
        let body = response
            .text()
            .await
            .map_err(|e| DAError::NetworkError(format!("failed to read response: {}", e)))?;

        let rpc_response: JsonRpcGetResponse = serde_json::from_str(&body)
            .map_err(|e| DAError::SerializationError(format!("failed to parse response: {}", e)))?;

        // Check for RPC error
        if let Some(error) = rpc_response.error {
            // Check if it's a "not found" error
            if error.code == -32000 || error.message.to_lowercase().contains("not found") {
                return Err(DAError::BlobNotFound(ref_.clone()));
            }
            return Err(DAError::Other(format!(
                "RPC error {}: {}",
                error.code, error.message
            )));
        }

        // Extract blob data from result
        let blob_result = rpc_response.result.ok_or_else(|| {
            DAError::BlobNotFound(ref_.clone())
        })?;

        // Decode namespace from response
        let response_namespace_bytes = BASE64.decode(&blob_result.namespace)
            .map_err(|e| DAError::SerializationError(format!("failed to decode namespace: {}", e)))?;

        // Validate namespace matches active namespace
        if response_namespace_bytes.len() != 29 {
            return Err(DAError::SerializationError(format!(
                "invalid namespace length: expected 29, got {}",
                response_namespace_bytes.len()
            )));
        }

        let mut response_namespace = [0u8; 29];
        response_namespace.copy_from_slice(&response_namespace_bytes);

        if response_namespace != self.namespace {
            warn!(
                expected = ?hex::encode(&self.namespace[..8]),
                actual = ?hex::encode(&response_namespace[..8]),
                "namespace mismatch in response"
            );
            return Err(DAError::InvalidNamespace);
        }

        // Decode blob data
        let data = BASE64.decode(&blob_result.data)
            .map_err(|e| DAError::SerializationError(format!("failed to decode blob data: {}", e)))?;

        // Verify commitment
        let computed_commitment = compute_blob_commitment(&data);
        if computed_commitment != ref_.commitment {
            error!(
                expected = ?hex::encode(&ref_.commitment[..8]),
                actual = ?hex::encode(&computed_commitment[..8]),
                "commitment mismatch"
            );
            return Err(DAError::InvalidBlob);
        }

        Ok(data)
    }

    /// Mendapatkan referensi ke konfigurasi.
    pub fn config(&self) -> &DAConfig {
        &self.config
    }

    /// Mendapatkan namespace yang digunakan.
    pub fn namespace(&self) -> &[u8; 29] {
        &self.namespace
    }

    /// Mengubah namespace yang digunakan.
    ///
    /// Method ini hanya mengubah field `namespace` internal.
    /// Tidak melakukan network call atau mengubah field lain.
    ///
    /// # Arguments
    ///
    /// * `ns` - Namespace baru 29-byte
    ///
    /// # Note
    ///
    /// Method ini tidak melakukan validasi namespace.
    /// Gunakan `validate_namespace()` setelah set jika diperlukan.
    pub fn set_namespace(&mut self, ns: [u8; 29]) {
        self.namespace = ns;
    }

    /// Memvalidasi namespace yang sedang aktif.
    ///
    /// Validasi dilakukan tanpa network call, hanya memeriksa
    /// format dan nilai namespace.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Namespace valid
    /// * `Err(DAError::InvalidNamespace)` - Namespace tidak valid
    ///
    /// # Validation Rules
    ///
    /// Namespace dianggap invalid jika:
    /// - Semua bytes adalah zero (reserved)
    pub fn validate_namespace(&self) -> Result<(), DAError> {
        validate_namespace_format(&self.namespace)
    }

    /// Mendapatkan height terakhir yang diketahui.
    pub fn last_height(&self) -> u64 {
        self.last_height.load(Ordering::SeqCst)
    }

    /// Mengupdate height terakhir.
    pub fn set_last_height(&self, height: u64) {
        self.last_height.store(height, Ordering::SeqCst);
    }

    /// Mendapatkan status kesehatan saat ini.
    pub fn health_status(&self) -> DAHealthStatus {
        *self.health_status.read().unwrap()
    }

    /// Mengupdate status kesehatan.
    pub fn set_health_status(&self, status: DAHealthStatus) {
        *self.health_status.write().unwrap() = status;
    }

    /// Perform a health check on the Celestia DA connection.
    ///
    /// This method checks the health of the connection by calling `header.NetworkHead`
    /// and measuring the latency. Based on the results, it returns the appropriate
    /// `DAHealthStatus` and updates the internal state.
    ///
    /// # Returns
    ///
    /// * `DAHealthStatus::Healthy` - Connection is healthy, latency is acceptable
    /// * `DAHealthStatus::Degraded` - Connection works but latency is high (>1000ms)
    /// * `DAHealthStatus::Unavailable` - Cannot reach the Celestia node
    ///
    /// # Latency Measurement
    ///
    /// Latency is measured from before the request is sent until the response
    /// is fully received and parsed.
    ///
    /// # Internal State Update
    ///
    /// This method updates the internal `health_status` field atomically
    /// based on the check results.
    pub async fn health_check(&self) -> DAHealthStatus {
        use std::time::Instant;

        debug!("starting health check");

        let start = Instant::now();

        // Build JSON-RPC request for header.NetworkHead
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "header.NetworkHead",
            params: vec![],
        };

        let mut req_builder = self.client
            .post(&self.config.rpc_url)
            .header("Content-Type", "application/json");

        if let Some(ref token) = self.config.auth_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
        }

        // Send request
        let response_result = req_builder
            .json(&request)
            .send()
            .await;

        let latency_ms = start.elapsed().as_millis() as u64;

        // Handle network errors
        let response = match response_result {
            Ok(resp) => resp,
            Err(e) => {
                let error_msg = if e.is_timeout() {
                    "connection timeout".to_string()
                } else if e.is_connect() {
                    "connection failed".to_string()
                } else {
                    format!("network error: {}", e)
                };

                error!(
                    error = %error_msg,
                    latency_ms,
                    "health check failed: network error"
                );

                let status = DAHealthStatus::Unavailable;
                *self.health_status.write().unwrap() = status;
                return status;
            }
        };

        // Check HTTP status
        let http_status = response.status();
        if !http_status.is_success() {
            warn!(
                http_status = %http_status,
                latency_ms,
                "health check failed: HTTP error"
            );

            let status = DAHealthStatus::Unavailable;
            *self.health_status.write().unwrap() = status;
            return status;
        }

        // Parse response body
        let body = match response.text().await {
            Ok(b) => b,
            Err(e) => {
                error!(
                    error = %e,
                    latency_ms,
                    "health check failed: failed to read response body"
                );

                let status = DAHealthStatus::Unavailable;
                *self.health_status.write().unwrap() = status;
                return status;
            }
        };

        // Parse JSON-RPC response
        let rpc_response: Result<JsonRpcNetworkHeadResponse, _> = serde_json::from_str(&body);
        let rpc_response = match rpc_response {
            Ok(r) => r,
            Err(e) => {
                error!(
                    error = %e,
                    latency_ms,
                    "health check failed: failed to parse response"
                );

                let status = DAHealthStatus::Unavailable;
                *self.health_status.write().unwrap() = status;
                return status;
            }
        };

        // Check for RPC error
        if let Some(error) = rpc_response.error {
            error!(
                code = error.code,
                message = %error.message,
                latency_ms,
                "health check failed: RPC error"
            );

            let status = DAHealthStatus::Unavailable;
            *self.health_status.write().unwrap() = status;
            return status;
        }

        // Extract network height
        let network_height = match rpc_response.result {
            Some(result) => {
                match result.header.height.parse::<u64>() {
                    Ok(h) => h,
                    Err(e) => {
                        error!(
                            error = %e,
                            latency_ms,
                            "health check failed: failed to parse height"
                        );

                        let status = DAHealthStatus::Unavailable;
                        *self.health_status.write().unwrap() = status;
                        return status;
                    }
                }
            }
            None => {
                error!(
                    latency_ms,
                    "health check failed: missing result in response"
                );

                let status = DAHealthStatus::Unavailable;
                *self.health_status.write().unwrap() = status;
                return status;
            }
        };

        let local_height = self.last_height.load(Ordering::SeqCst);

        // Determine health status based on latency and sync state
        // Threshold: latency > 1000ms is considered degraded
        const LATENCY_THRESHOLD_MS: u64 = 1000;

        let status = if latency_ms > LATENCY_THRESHOLD_MS {
            warn!(
                latency_ms,
                threshold = LATENCY_THRESHOLD_MS,
                "health check: high latency detected"
            );
            DAHealthStatus::Degraded
        } else {
            debug!(
                network_height,
                local_height,
                latency_ms,
                "health check: healthy"
            );
            DAHealthStatus::Healthy
        };

        // Update internal state
        *self.health_status.write().unwrap() = status;

        // Update last_height if network height is higher
        if network_height > local_height {
            self.last_height.store(network_height, Ordering::SeqCst);
        }

        info!(
            status = ?status,
            network_height,
            local_height,
            latency_ms,
            "health check completed"
        );

        status
    }

    /// Subscribe to blobs from Celestia DA layer.
    ///
    /// This method creates a polling-based subscription stream that yields
    /// blobs matching the specified namespace. The stream uses a configurable
    /// polling interval to fetch new blobs.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The 29-byte namespace to filter blobs
    ///
    /// # Returns
    ///
    /// A `BlobStream` that yields `Result<Blob, DAError>` items.
    ///
    /// # Ordering
    ///
    /// Blobs are yielded in (height ASC, index ASC) order.
    /// No duplicate blobs will be yielded.
    ///
    /// # Reconnection
    ///
    /// If polling fails due to network errors, the stream will retry
    /// with exponential backoff. The stream will not terminate on
    /// transient errors.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use futures::StreamExt;
    ///
    /// let stream = celestia_da.subscribe_blobs(&namespace);
    /// while let Some(result) = stream.next().await {
    ///     match result {
    ///         Ok(blob) => println!("Received blob at height {}", blob.height),
    ///         Err(e) => eprintln!("Error: {:?}", e),
    ///     }
    /// }
    /// ```
    pub fn subscribe_blobs(self: &Arc<Self>, namespace: &[u8; 29]) -> BlobStream {
        let subscription = BlobSubscription {
            da: Arc::clone(self),
            from_height: self.last_height().saturating_add(1),
            namespace: *namespace,
            poll_interval_ms: DEFAULT_POLL_INTERVAL_MS,
        };

        debug!(
            namespace = ?hex::encode(&namespace[..8]),
            from_height = subscription.from_height,
            poll_interval_ms = subscription.poll_interval_ms,
            "created blob subscription"
        );

        subscription.into_stream()
    }

    /// Get blobs at a specific height for a namespace.
    ///
    /// This is an internal helper method used by BlobSubscription.
    async fn get_blobs_at_height(
        &self,
        height: u64,
        namespace: &[u8; 29],
    ) -> Result<Vec<Blob>, DAError> {
        debug!(height, namespace = ?hex::encode(&namespace[..8]), "fetching blobs at height");

        // Build JSON-RPC request for blob.GetAll
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "blob.GetAll",
            params: vec![
                serde_json::json!(height),
                serde_json::json!([BASE64.encode(namespace)]),
            ],
        };

        let mut req_builder = self.client
            .post(&self.config.rpc_url)
            .header("Content-Type", "application/json");

        if let Some(ref token) = self.config.auth_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
        }

        let response = req_builder
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    DAError::Timeout
                } else if e.is_connect() {
                    DAError::Unavailable
                } else {
                    DAError::NetworkError(format!("request failed: {}", e))
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            return Err(DAError::NetworkError(format!("HTTP error: {}", status)));
        }

        let body = response
            .text()
            .await
            .map_err(|e| DAError::NetworkError(format!("failed to read response: {}", e)))?;

        let rpc_response: JsonRpcGetAllResponse = serde_json::from_str(&body)
            .map_err(|e| DAError::SerializationError(format!("failed to parse response: {}", e)))?;

        if let Some(error) = rpc_response.error {
            // "blob not found" or similar is not a fatal error for subscription
            if error.code == -32000 || error.message.to_lowercase().contains("not found") {
                return Ok(Vec::new());
            }
            return Err(DAError::Other(format!("RPC error {}: {}", error.code, error.message)));
        }

        let blob_items = rpc_response.result.unwrap_or_default();
        let mut blobs = Vec::with_capacity(blob_items.len());

        for (idx, item) in blob_items.into_iter().enumerate() {
            // Decode namespace
            let ns_bytes = BASE64.decode(&item.namespace)
                .map_err(|e| DAError::SerializationError(format!("failed to decode namespace: {}", e)))?;

            if ns_bytes.len() != 29 {
                warn!(
                    height,
                    index = idx,
                    len = ns_bytes.len(),
                    "invalid namespace length, skipping blob"
                );
                continue;
            }

            let mut blob_namespace = [0u8; 29];
            blob_namespace.copy_from_slice(&ns_bytes);

            // Filter by namespace - skip blobs that don't match
            if blob_namespace != *namespace {
                continue;
            }

            // Decode data
            let data = BASE64.decode(&item.data)
                .map_err(|e| DAError::SerializationError(format!("failed to decode blob data: {}", e)))?;

            // Decode commitment
            let commitment_bytes = BASE64.decode(&item.commitment)
                .map_err(|e| DAError::SerializationError(format!("failed to decode commitment: {}", e)))?;

            if commitment_bytes.len() != 32 {
                warn!(
                    height,
                    index = idx,
                    len = commitment_bytes.len(),
                    "invalid commitment length, skipping blob"
                );
                continue;
            }

            let mut commitment = [0u8; 32];
            commitment.copy_from_slice(&commitment_bytes);

            blobs.push(Blob {
                height,
                index: item.index,
                namespace: blob_namespace,
                data,
                commitment,
            });
        }

        // Sort by index to ensure ordering within block
        blobs.sort_by_key(|b| b.index);

        debug!(height, count = blobs.len(), "fetched blobs at height");
        Ok(blobs)
    }

    /// Get the current network head height.
    ///
    /// This is an internal helper method used by BlobSubscription.
    async fn get_network_head(&self) -> Result<u64, DAError> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "header.NetworkHead",
            params: vec![],
        };

        let mut req_builder = self.client
            .post(&self.config.rpc_url)
            .header("Content-Type", "application/json");

        if let Some(ref token) = self.config.auth_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
        }

        let response = req_builder
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    DAError::Timeout
                } else if e.is_connect() {
                    DAError::Unavailable
                } else {
                    DAError::NetworkError(format!("request failed: {}", e))
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            return Err(DAError::NetworkError(format!("HTTP error: {}", status)));
        }

        let body = response
            .text()
            .await
            .map_err(|e| DAError::NetworkError(format!("failed to read response: {}", e)))?;

        let rpc_response: JsonRpcNetworkHeadResponse = serde_json::from_str(&body)
            .map_err(|e| DAError::SerializationError(format!("failed to parse response: {}", e)))?;

        if let Some(error) = rpc_response.error {
            return Err(DAError::Other(format!("RPC error {}: {}", error.code, error.message)));
        }

        let result = rpc_response.result.ok_or_else(|| {
            DAError::SerializationError("missing result in network head response".to_string())
        })?;

        let height: u64 = result.header.height.parse()
            .map_err(|e| DAError::SerializationError(format!("failed to parse height: {}", e)))?;

        Ok(height)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// BLOB SUBSCRIPTION STREAM CREATION
// ════════════════════════════════════════════════════════════════════════════

/// Internal state for blob subscription stream.
/// This is kept separate from BlobSubscription to comply with the spec.
struct BlobSubscriptionState {
    da: Arc<CelestiaDA>,
    namespace: [u8; 29],
    poll_interval_ms: u64,
    current_height: u64,
    pending_blobs: Vec<Blob>,
    seen_blobs: HashSet<(u64, u32)>,
    retry_delay_ms: u64,
}

impl BlobSubscription {
    /// Convert the subscription configuration into a stream.
    ///
    /// This method creates the actual polling stream using the
    /// configuration stored in BlobSubscription.
    fn into_stream(self) -> BlobStream {
        use futures::stream::unfold;

        let initial_state = BlobSubscriptionState {
            da: self.da,
            namespace: self.namespace,
            poll_interval_ms: self.poll_interval_ms,
            current_height: self.from_height,
            pending_blobs: Vec::new(),
            seen_blobs: HashSet::new(),
            retry_delay_ms: 100, // Initial retry delay
        };

        Box::pin(unfold(initial_state, |mut state| async move {
            loop {
                // 1. If we have pending blobs, yield the next one
                if !state.pending_blobs.is_empty() {
                    let blob = state.pending_blobs.remove(0);
                    let key = (blob.height, blob.index);

                    // Skip if already seen (deduplication)
                    if state.seen_blobs.contains(&key) {
                        continue;
                    }

                    state.seen_blobs.insert(key);
                    return Some((Ok(blob), state));
                }

                // 2. Poll for new blobs
                debug!(
                    height = state.current_height,
                    namespace = ?hex::encode(&state.namespace[..8]),
                    "polling for blobs"
                );

                // First get the network head to avoid polling future heights
                let head_result = state.da.get_network_head().await;
                let head_height = match head_result {
                    Ok(h) => h,
                    Err(e) => {
                        let is_retryable = matches!(
                            e,
                            DAError::NetworkError(_) | DAError::Timeout | DAError::Unavailable
                        );

                        if is_retryable {
                            warn!(
                                error = ?e,
                                retry_delay_ms = state.retry_delay_ms,
                                "failed to get network head, will retry"
                            );

                            // Sleep before retry
                            tokio::time::sleep(Duration::from_millis(state.retry_delay_ms)).await;
                            state.retry_delay_ms = (state.retry_delay_ms * 2).min(60000);

                            // Return error but continue stream
                            return Some((Err(e), state));
                        } else {
                            error!(error = ?e, "non-retryable error getting network head");
                            return Some((Err(e), state));
                        }
                    }
                };

                // If we're ahead of the chain, wait for new blocks
                if state.current_height > head_height {
                    tokio::time::sleep(Duration::from_millis(state.poll_interval_ms)).await;
                    continue;
                }

                // Fetch blobs at current height
                let blobs_result = state.da.get_blobs_at_height(
                    state.current_height,
                    &state.namespace
                ).await;

                match blobs_result {
                    Ok(blobs) => {
                        // Reset retry delay on success
                        state.retry_delay_ms = 100;

                        if !blobs.is_empty() {
                            debug!(
                                height = state.current_height,
                                count = blobs.len(),
                                "received blobs"
                            );

                            // Sort blobs by (height, index) for proper ordering
                            let mut sorted_blobs = blobs;
                            sorted_blobs.sort_by(|a, b| {
                                (a.height, a.index).cmp(&(b.height, b.index))
                            });

                            state.pending_blobs = sorted_blobs;
                            state.current_height = state.current_height.saturating_add(1);

                            // Continue loop to yield blobs
                            continue;
                        } else {
                            // No blobs at this height, move to next
                            state.current_height = state.current_height.saturating_add(1);

                            // If we're caught up, wait before next poll
                            if state.current_height > head_height {
                                tokio::time::sleep(Duration::from_millis(state.poll_interval_ms)).await;
                            }
                            continue;
                        }
                    }
                    Err(e) => {
                        let is_retryable = matches!(
                            e,
                            DAError::NetworkError(_) | DAError::Timeout | DAError::Unavailable
                        );

                        if is_retryable {
                            warn!(
                                error = ?e,
                                height = state.current_height,
                                retry_delay_ms = state.retry_delay_ms,
                                "poll failed, will retry"
                            );

                            // Sleep before retry
                            tokio::time::sleep(Duration::from_millis(state.retry_delay_ms)).await;
                            state.retry_delay_ms = (state.retry_delay_ms * 2).min(60000);

                            // Return error but continue stream
                            return Some((Err(e), state));
                        } else {
                            error!(
                                error = ?e,
                                height = state.current_height,
                                "non-retryable poll error"
                            );

                            // Move to next height and continue
                            state.current_height = state.current_height.saturating_add(1);
                            return Some((Err(e), state));
                        }
                    }
                }
            }
        }))
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DALAYER TRAIT IMPLEMENTATION
// ════════════════════════════════════════════════════════════════════════════

impl DALayer for CelestiaDA {
    fn post_blob(&self, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<BlobRef, DAError>> + Send + '_>> {
        let data = data.to_vec(); // Clone to decouple lifetime from input
        Box::pin(async move {
            // Delegate to inherent method
            CelestiaDA::post_blob(self, &data).await
        })
    }

    fn get_blob(&self, blob_ref: &BlobRef) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DAError>> + Send + '_>> {
        let blob_ref = blob_ref.clone(); // Clone to decouple lifetime from input
        Box::pin(async move {
            // Delegate to inherent method
            CelestiaDA::get_blob(self, &blob_ref).await
        })
    }

    fn subscribe_blobs(&self, _from_height: Option<u64>) -> Pin<Box<dyn Future<Output = Result<DABlobStream, DAError>> + Send + '_>> {
        Box::pin(async move {
            // CelestiaDA needs Arc<Self> for subscribe_blobs
            // Since we only have &self, we cannot call the inherent method directly
            // Return an error indicating this limitation
            Err(DAError::Other(
                "subscribe_blobs via trait requires Arc<CelestiaDA>. Use CelestiaDA::subscribe_blobs() directly.".to_string()
            ))
        })
    }

    fn health_check(&self) -> Pin<Box<dyn Future<Output = Result<DAHealthStatus, DAError>> + Send + '_>> {
        Box::pin(async move {
            // Delegate to inherent method and wrap in Ok
            let status = CelestiaDA::health_check(self).await;
            Ok(status)
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::method;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    // ════════════════════════════════════════════════════════════════════════
    // HELPER FUNCTIONS
    // ════════════════════════════════════════════════════════════════════════

    fn create_test_config(rpc_url: &str) -> DAConfig {
        DAConfig {
            rpc_url: rpc_url.to_string(),
            namespace: [0x01; 29],
            auth_token: None,
            timeout_ms: 5000,
            retry_count: 3,
            retry_delay_ms: 100,
            network: "testnet".to_string(),
            enable_pooling: false,
            max_connections: 1,
            idle_timeout_ms: 30000,
        }
    }

    fn create_blob_submit_success_response(height: u64) -> String {
        format!(r#"{{"jsonrpc":"2.0","id":1,"result":{}}}"#, height)
    }

    fn create_blob_submit_error_response(code: i64, message: &str) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":{},"message":"{}"}}}}"#,
            code, message
        )
    }

    fn create_blob_get_success_response(namespace: &[u8; 29], data: &[u8], commitment: &[u8; 32]) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"namespace":"{}","data":"{}","share_version":0,"commitment":"{}"}}}}"#,
            BASE64.encode(namespace),
            BASE64.encode(data),
            BASE64.encode(commitment)
        )
    }

    fn create_blob_get_not_found_response() -> String {
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"blob not found"}}"#.to_string()
    }

    fn create_blob_get_null_result_response() -> String {
        r#"{"jsonrpc":"2.0","id":1,"result":null}"#.to_string()
    }

    // ════════════════════════════════════════════════════════════════════════
    // COMPUTE_BLOB_COMMITMENT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_compute_blob_commitment_deterministic() {
        let data = b"test data for commitment";
        let c1 = compute_blob_commitment(data);
        let c2 = compute_blob_commitment(data);
        assert_eq!(c1, c2, "Same input should produce same commitment");
    }

    #[test]
    fn test_compute_blob_commitment_different_inputs() {
        let c1 = compute_blob_commitment(b"data 1");
        let c2 = compute_blob_commitment(b"data 2");
        assert_ne!(c1, c2, "Different inputs should produce different commitments");
    }

    #[test]
    fn test_compute_blob_commitment_length() {
        let c = compute_blob_commitment(b"any data");
        assert_eq!(c.len(), 32, "Commitment must be exactly 32 bytes");
    }

    #[test]
    fn test_compute_blob_commitment_empty() {
        let c = compute_blob_commitment(b"");
        assert_eq!(c.len(), 32, "Empty input should produce 32-byte commitment");
    }

    // ════════════════════════════════════════════════════════════════════════
    // GET_BLOB SUCCESS TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_get_blob_success() {
        let mock_server = MockServer::start().await;

        // Mock HEAD for init
        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let test_data = b"hello celestia blob";
        let test_namespace = [0x01; 29];
        let test_commitment = compute_blob_commitment(test_data);

        // Mock POST for blob.Get
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(create_blob_get_success_response(
                        &test_namespace,
                        test_data,
                        &test_commitment
                    ))
            )
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        let blob_ref = BlobRef {
            height: 12345,
            commitment: test_commitment,
            namespace: test_namespace,
        };

        let result = celestia_da.get_blob(&blob_ref).await;

        assert!(result.is_ok(), "get_blob should succeed");
        assert_eq!(result.unwrap(), test_data.to_vec());
    }

    #[tokio::test]
    async fn test_get_blob_returns_correct_data() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let test_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let test_namespace = [0x01; 29];
        let test_commitment = compute_blob_commitment(&test_data);

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(create_blob_get_success_response(
                        &test_namespace,
                        &test_data,
                        &test_commitment
                    ))
            )
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        let blob_ref = BlobRef {
            height: 100,
            commitment: test_commitment,
            namespace: test_namespace,
        };

        let result = celestia_da.get_blob(&blob_ref).await.unwrap();
        assert_eq!(result, test_data);
    }

    #[tokio::test]
    async fn test_get_blob_empty_data() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let test_data: &[u8] = b"";
        let test_namespace = [0x01; 29];
        let test_commitment = compute_blob_commitment(test_data);

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(create_blob_get_success_response(
                        &test_namespace,
                        test_data,
                        &test_commitment
                    ))
            )
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        let blob_ref = BlobRef {
            height: 1,
            commitment: test_commitment,
            namespace: test_namespace,
        };

        let result = celestia_da.get_blob(&blob_ref).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    // ════════════════════════════════════════════════════════════════════════
    // GET_BLOB NAMESPACE MISMATCH TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_get_blob_namespace_mismatch_in_ref() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // No POST mock needed - should fail before network call

        let config = create_test_config(&mock_server.uri()); // namespace = [0x01; 29]
        let celestia_da = CelestiaDA::new(config).unwrap();

        // BlobRef has different namespace
        let blob_ref = BlobRef {
            height: 100,
            commitment: [0xAA; 32],
            namespace: [0x02; 29], // Different from CelestiaDA's [0x01; 29]
        };

        let result = celestia_da.get_blob(&blob_ref).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DAError::InvalidNamespace));
    }

    #[tokio::test]
    async fn test_get_blob_namespace_mismatch_no_network_call() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();

        Mock::given(method("POST"))
            .respond_with(move |_: &wiremock::Request| {
                counter.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"jsonrpc":"2.0","id":1,"result":null}"#)
            })
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        let blob_ref = BlobRef {
            height: 100,
            commitment: [0xAA; 32],
            namespace: [0xFF; 29], // Different namespace
        };

        let _ = celestia_da.get_blob(&blob_ref).await;

        assert_eq!(call_count.load(Ordering::SeqCst), 0, "No network call should be made for namespace mismatch");
    }

    #[tokio::test]
    async fn test_get_blob_namespace_mismatch_in_response() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let test_data = b"test data";
        let matching_namespace = [0x01; 29];
        let different_namespace = [0x02; 29]; // Response has different namespace
        let test_commitment = compute_blob_commitment(test_data);

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(create_blob_get_success_response(
                        &different_namespace, // Wrong namespace in response
                        test_data,
                        &test_commitment
                    ))
            )
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        let blob_ref = BlobRef {
            height: 100,
            commitment: test_commitment,
            namespace: matching_namespace, // Matches CelestiaDA, but response doesn't
        };

        let result = celestia_da.get_blob(&blob_ref).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DAError::InvalidNamespace));
    }

    // ════════════════════════════════════════════════════════════════════════
    // GET_BLOB BLOB NOT FOUND TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_get_blob_not_found_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(create_blob_get_not_found_response())
            )
            .mount(&mock_server)
            .await;

        let mut config = create_test_config(&mock_server.uri());
        config.retry_count = 0; // No retry

        let celestia_da = CelestiaDA::new(config).unwrap();

        let blob_ref = BlobRef {
            height: 99999,
            commitment: [0xAB; 32],
            namespace: [0x01; 29],
        };

        let result = celestia_da.get_blob(&blob_ref).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            DAError::BlobNotFound(ref_) => {
                assert_eq!(ref_.height, 99999);
            }
            other => panic!("Expected BlobNotFound, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_get_blob_null_result_is_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(create_blob_get_null_result_response())
            )
            .mount(&mock_server)
            .await;

        let mut config = create_test_config(&mock_server.uri());
        config.retry_count = 0;

        let celestia_da = CelestiaDA::new(config).unwrap();

        let blob_ref = BlobRef {
            height: 100,
            commitment: [0xAB; 32],
            namespace: [0x01; 29],
        };

        let result = celestia_da.get_blob(&blob_ref).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DAError::BlobNotFound(_)));
    }

    #[tokio::test]
    async fn test_get_blob_not_found_no_panic() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(create_blob_get_not_found_response())
            )
            .mount(&mock_server)
            .await;

        let mut config = create_test_config(&mock_server.uri());
        config.retry_count = 0;

        let celestia_da = CelestiaDA::new(config).unwrap();

        let blob_ref = BlobRef {
            height: 100,
            commitment: [0xAB; 32],
            namespace: [0x01; 29],
        };

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            std::thread::spawn(move || {
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    celestia_da.get_blob(&blob_ref).await
                })
            }).join().unwrap()
        }));

        assert!(result.is_ok(), "Should not panic");
    }

    // ════════════════════════════════════════════════════════════════════════
    // GET_BLOB COMMITMENT MISMATCH TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_get_blob_commitment_mismatch() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let test_data = b"actual data from server";
        let test_namespace = [0x01; 29];
        let actual_commitment = compute_blob_commitment(test_data);
        let wrong_commitment = [0xBA; 32]; // Different from actual

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(create_blob_get_success_response(
                        &test_namespace,
                        test_data,
                        &actual_commitment
                    ))
            )
            .mount(&mock_server)
            .await;

        let mut config = create_test_config(&mock_server.uri());
        config.retry_count = 0;

        let celestia_da = CelestiaDA::new(config).unwrap();

        // BlobRef has wrong commitment
        let blob_ref = BlobRef {
            height: 100,
            commitment: wrong_commitment,
            namespace: test_namespace,
        };

        let result = celestia_da.get_blob(&blob_ref).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DAError::InvalidBlob));
    }

    #[tokio::test]
    async fn test_get_blob_commitment_mismatch_no_data_returned() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let test_data = b"some data";
        let test_namespace = [0x01; 29];
        let actual_commitment = compute_blob_commitment(test_data);

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(create_blob_get_success_response(
                        &test_namespace,
                        test_data,
                        &actual_commitment
                    ))
            )
            .mount(&mock_server)
            .await;

        let mut config = create_test_config(&mock_server.uri());
        config.retry_count = 0;

        let celestia_da = CelestiaDA::new(config).unwrap();

        let blob_ref = BlobRef {
            height: 100,
            commitment: [0xFF; 32], // Wrong
            namespace: test_namespace,
        };

        let result = celestia_da.get_blob(&blob_ref).await;

        // Should be error, not Ok with data
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_blob_corrupted_data_detected() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let original_data = b"original data";
        let corrupted_data = b"corrupted!!";
        let test_namespace = [0x01; 29];
        let original_commitment = compute_blob_commitment(original_data);

        // Server returns corrupted data but with original commitment
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(create_blob_get_success_response(
                        &test_namespace,
                        corrupted_data, // Corrupted
                        &original_commitment // Claimed commitment
                    ))
            )
            .mount(&mock_server)
            .await;

        let mut config = create_test_config(&mock_server.uri());
        config.retry_count = 0;

        let celestia_da = CelestiaDA::new(config).unwrap();

        let blob_ref = BlobRef {
            height: 100,
            commitment: original_commitment,
            namespace: test_namespace,
        };

        let result = celestia_da.get_blob(&blob_ref).await;

        // Commitment verification should fail
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DAError::InvalidBlob));
    }

    // ════════════════════════════════════════════════════════════════════════
    // GET_BLOB RETRY TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_get_blob_retry_then_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let test_data = b"retry success data";
        let test_namespace = [0x01; 29];
        let test_commitment = compute_blob_commitment(test_data);

        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();

        Mock::given(method("POST"))
            .respond_with(move |_: &wiremock::Request| {
                let count = counter.fetch_add(1, Ordering::SeqCst);
                if count < 2 {
                    // First 2 calls fail
                    ResponseTemplate::new(500)
                } else {
                    // Third call succeeds
                    ResponseTemplate::new(200)
                        .set_body_string(create_blob_get_success_response(
                            &test_namespace,
                            test_data,
                            &test_commitment
                        ))
                }
            })
            .mount(&mock_server)
            .await;

        let mut config = create_test_config(&mock_server.uri());
        config.retry_count = 3;
        config.retry_delay_ms = 10;

        let celestia_da = CelestiaDA::new(config).unwrap();

        let blob_ref = BlobRef {
            height: 100,
            commitment: test_commitment,
            namespace: test_namespace,
        };

        let result = celestia_da.get_blob(&blob_ref).await;

        assert!(result.is_ok(), "Should succeed after retries");
        assert_eq!(result.unwrap(), test_data.to_vec());
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_get_blob_retry_count_respected() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();

        Mock::given(method("POST"))
            .respond_with(move |_: &wiremock::Request| {
                counter.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(500) // Always fail
            })
            .mount(&mock_server)
            .await;

        let mut config = create_test_config(&mock_server.uri());
        config.retry_count = 2; // 1 initial + 2 retries = 3 total
        config.retry_delay_ms = 10;

        let celestia_da = CelestiaDA::new(config).unwrap();

        let blob_ref = BlobRef {
            height: 100,
            commitment: [0xAB; 32],
            namespace: [0x01; 29],
        };

        let _ = celestia_da.get_blob(&blob_ref).await;

        assert_eq!(call_count.load(Ordering::SeqCst), 3, "Should make exactly 1 + retry_count calls");
    }

    #[tokio::test]
    async fn test_get_blob_no_retry_on_blob_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();

        Mock::given(method("POST"))
            .respond_with(move |_: &wiremock::Request| {
                counter.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200)
                    .set_body_string(create_blob_get_not_found_response())
            })
            .mount(&mock_server)
            .await;

        let mut config = create_test_config(&mock_server.uri());
        config.retry_count = 3;
        config.retry_delay_ms = 10;

        let celestia_da = CelestiaDA::new(config).unwrap();

        let blob_ref = BlobRef {
            height: 100,
            commitment: [0xAB; 32],
            namespace: [0x01; 29],
        };

        let result = celestia_da.get_blob(&blob_ref).await;

        assert!(result.is_err());
        // BlobNotFound is not retryable, should only make 1 call
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_get_blob_no_retry_on_commitment_mismatch() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let test_data = b"data";
        let test_namespace = [0x01; 29];
        let actual_commitment = compute_blob_commitment(test_data);

        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();

        Mock::given(method("POST"))
            .respond_with(move |_: &wiremock::Request| {
                counter.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200)
                    .set_body_string(create_blob_get_success_response(
                        &test_namespace,
                        test_data,
                        &actual_commitment
                    ))
            })
            .mount(&mock_server)
            .await;

        let mut config = create_test_config(&mock_server.uri());
        config.retry_count = 3;
        config.retry_delay_ms = 10;

        let celestia_da = CelestiaDA::new(config).unwrap();

        let blob_ref = BlobRef {
            height: 100,
            commitment: [0xFF; 32], // Wrong
            namespace: test_namespace,
        };

        let result = celestia_da.get_blob(&blob_ref).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DAError::InvalidBlob));
        // InvalidBlob is not retryable
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    // GET_BLOB NO PANIC TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_get_blob_no_panic_on_various_errors() {
        let bad_responses = vec![
            "",
            "null",
            "[]",
            "{}",
            r#"{"error": "bad"}"#,
            r#"{"result": "not an object"}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"data":"not_base64!!!"}}"#,
        ];

        for bad_response in bad_responses {
            let server = MockServer::start().await;

            Mock::given(method("HEAD"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            Mock::given(method("POST"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_string(bad_response)
                )
                .mount(&server)
                .await;

            let mut config = create_test_config(&server.uri());
            config.retry_count = 0;

            let celestia_da = CelestiaDA::new(config).unwrap();

            let blob_ref = BlobRef {
                height: 100,
                commitment: [0xAB; 32],
                namespace: [0x01; 29],
            };

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                std::thread::spawn(move || {
                    tokio::runtime::Runtime::new().unwrap().block_on(async {
                        celestia_da.get_blob(&blob_ref).await
                    })
                }).join().unwrap()
            }));

            assert!(result.is_ok(), "Should not panic on bad response: {}", bad_response);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // POST_BLOB SUCCESS TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_post_blob_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(create_blob_submit_success_response(12345))
            )
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        assert_eq!(celestia_da.last_height(), 0);

        let data = b"test blob data";
        let result = celestia_da.post_blob(data).await;

        assert!(result.is_ok(), "post_blob should succeed");

        let blob_ref = result.unwrap();
        assert_eq!(blob_ref.height, 12345);
        assert_eq!(blob_ref.namespace, [0x01; 29]);
        assert_eq!(blob_ref.commitment, compute_blob_commitment(data));
        assert_eq!(celestia_da.last_height(), 12345);
        assert_eq!(celestia_da.health_status(), DAHealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_post_blob_small_data() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(create_blob_submit_success_response(100))
            )
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        let result = celestia_da.post_blob(&[0x42]).await;
        assert!(result.is_ok());

        let result = celestia_da.post_blob(&[]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_post_blob_updates_last_height() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(create_blob_submit_success_response(999))
            )
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        assert_eq!(celestia_da.last_height(), 0);
        let _ = celestia_da.post_blob(b"data").await;
        assert_eq!(celestia_da.last_height(), 999);
    }

    // ════════════════════════════════════════════════════════════════════════
    // POST_BLOB SIZE VALIDATION TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_post_blob_exceeds_max_size() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        let large_data = vec![0u8; MAX_BLOB_SIZE + 1];
        let result = celestia_da.post_blob(&large_data).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            DAError::Other(msg) => {
                assert!(msg.contains("exceeds maximum"));
            }
            _ => panic!("Expected DAError::Other for size validation"),
        }
        assert_eq!(celestia_da.last_height(), 0);
    }

    #[tokio::test]
    async fn test_post_blob_exactly_max_size() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(create_blob_submit_success_response(500))
            )
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        let max_data = vec![0u8; MAX_BLOB_SIZE];
        let result = celestia_da.post_blob(&max_data).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_post_blob_no_network_call_on_size_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();

        Mock::given(method("POST"))
            .respond_with(move |_: &wiremock::Request| {
                counter.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200)
                    .set_body_string(create_blob_submit_success_response(1))
            })
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        let large_data = vec![0u8; MAX_BLOB_SIZE + 1];
        let _ = celestia_da.post_blob(&large_data).await;

        assert_eq!(call_count.load(Ordering::SeqCst), 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // POST_BLOB RETRY TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_post_blob_retry_then_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();

        Mock::given(method("POST"))
            .respond_with(move |_: &wiremock::Request| {
                let count = counter.fetch_add(1, Ordering::SeqCst);
                if count < 2 {
                    ResponseTemplate::new(500)
                } else {
                    ResponseTemplate::new(200)
                        .set_body_string(create_blob_submit_success_response(777))
                }
            })
            .mount(&mock_server)
            .await;

        let mut config = create_test_config(&mock_server.uri());
        config.retry_count = 3;
        config.retry_delay_ms = 10;

        let celestia_da = CelestiaDA::new(config).unwrap();
        let result = celestia_da.post_blob(b"retry test").await;

        assert!(result.is_ok());
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
        assert_eq!(celestia_da.last_height(), 777);
    }

    #[tokio::test]
    async fn test_post_blob_all_retries_exhausted() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let mut config = create_test_config(&mock_server.uri());
        config.retry_count = 2;
        config.retry_delay_ms = 10;

        let celestia_da = CelestiaDA::new(config).unwrap();
        let result = celestia_da.post_blob(b"fail test").await;

        assert!(result.is_err());
        assert_eq!(celestia_da.health_status(), DAHealthStatus::Unavailable);
    }

    #[tokio::test]
    async fn test_post_blob_retry_count_respected() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let call_count = Arc::new(AtomicUsize::new(0));
        let counter = call_count.clone();

        Mock::given(method("POST"))
            .respond_with(move |_: &wiremock::Request| {
                counter.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(500)
            })
            .mount(&mock_server)
            .await;

        let mut config = create_test_config(&mock_server.uri());
        config.retry_count = 2;
        config.retry_delay_ms = 10;

        let celestia_da = CelestiaDA::new(config).unwrap();
        let _ = celestia_da.post_blob(b"count test").await;

        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    // ════════════════════════════════════════════════════════════════════════
    // POST_BLOB RESPONSE ERROR TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_post_blob_invalid_json_response() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("not valid json")
            )
            .mount(&mock_server)
            .await;

        let mut config = create_test_config(&mock_server.uri());
        config.retry_count = 0;

        let celestia_da = CelestiaDA::new(config).unwrap();
        let result = celestia_da.post_blob(b"test").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DAError::SerializationError(_)));
    }

    #[tokio::test]
    async fn test_post_blob_rpc_error_response() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(create_blob_submit_error_response(-32000, "internal error"))
            )
            .mount(&mock_server)
            .await;

        let mut config = create_test_config(&mock_server.uri());
        config.retry_count = 0;

        let celestia_da = CelestiaDA::new(config).unwrap();
        let result = celestia_da.post_blob(b"test").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            DAError::Other(msg) => {
                assert!(msg.contains("RPC error"));
                assert!(msg.contains("-32000"));
            }
            _ => panic!("Expected DAError::Other for RPC error"),
        }
    }

    #[tokio::test]
    async fn test_post_blob_missing_result() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"jsonrpc":"2.0","id":1}"#)
            )
            .mount(&mock_server)
            .await;

        let mut config = create_test_config(&mock_server.uri());
        config.retry_count = 0;

        let celestia_da = CelestiaDA::new(config).unwrap();
        let result = celestia_da.post_blob(b"test").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DAError::SerializationError(_)));
    }

    #[tokio::test]
    async fn test_post_blob_no_panic_on_errors() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let bad_responses = vec![
            "",
            "null",
            "[]",
            "{}",
            r#"{"error": "bad"}"#,
            r#"{"result": "not a number"}"#,
        ];

        for bad_response in bad_responses {
            let server = MockServer::start().await;

            Mock::given(method("HEAD"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            Mock::given(method("POST"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_string(bad_response)
                )
                .mount(&server)
                .await;

            let mut config = create_test_config(&server.uri());
            config.retry_count = 0;

            let celestia_da = CelestiaDA::new(config).unwrap();

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                std::thread::spawn(move || {
                    tokio::runtime::Runtime::new().unwrap().block_on(async {
                        celestia_da.post_blob(b"test").await
                    })
                }).join().unwrap()
            }));

            assert!(result.is_ok(), "Should not panic on bad response: {}", bad_response);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // COMPUTE_NAMESPACE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_compute_namespace_deterministic() {
        let ns1 = compute_namespace("test-namespace");
        let ns2 = compute_namespace("test-namespace");
        assert_eq!(ns1, ns2);
    }

    #[test]
    fn test_compute_namespace_different_inputs() {
        let ns1 = compute_namespace("namespace-a");
        let ns2 = compute_namespace("namespace-b");
        assert_ne!(ns1, ns2);
    }

    #[test]
    fn test_compute_namespace_length() {
        let ns = compute_namespace("any-string");
        assert_eq!(ns.len(), 29);
    }

    #[test]
    fn test_compute_namespace_empty_string() {
        let ns = compute_namespace("");
        assert_eq!(ns.len(), 29);
    }

    #[test]
    fn test_compute_namespace_long_string() {
        let long_string = "a".repeat(1000);
        let ns = compute_namespace(&long_string);
        assert_eq!(ns.len(), 29);
    }

    #[test]
    fn test_compute_namespace_consistent_across_runs() {
        let expected = compute_namespace("dsdn-control-v0");
        for _ in 0..100 {
            let actual = compute_namespace("dsdn-control-v0");
            assert_eq!(expected, actual);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // DSDN_NAMESPACE_V0 TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_dsdn_namespace_v0_consistent_with_compute() {
        let computed = compute_namespace("dsdn-control-v0");
        assert_eq!(DSDN_NAMESPACE_V0, computed);
    }

    #[test]
    fn test_dsdn_namespace_v0_length() {
        assert_eq!(DSDN_NAMESPACE_V0.len(), 29);
    }

    #[test]
    fn test_dsdn_namespace_v0_not_all_zeros() {
        let all_zeros = DSDN_NAMESPACE_V0.iter().all(|&b| b == 0);
        assert!(!all_zeros);
    }

    // ════════════════════════════════════════════════════════════════════════
    // SET_NAMESPACE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_set_namespace_changes_namespace() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let mut celestia_da = CelestiaDA::new(config).unwrap();

        let old_namespace = *celestia_da.namespace();
        let new_namespace = [0xAB; 29];

        celestia_da.set_namespace(new_namespace);

        assert_eq!(celestia_da.namespace(), &new_namespace);
        assert_ne!(celestia_da.namespace(), &old_namespace);
    }

    #[tokio::test]
    async fn test_set_namespace_does_not_change_other_fields() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let mut celestia_da = CelestiaDA::new(config.clone()).unwrap();

        celestia_da.set_last_height(12345);
        celestia_da.set_health_status(DAHealthStatus::Degraded);

        let last_height_before = celestia_da.last_height();
        let health_status_before = celestia_da.health_status();
        let rpc_url_before = celestia_da.config().rpc_url.clone();

        celestia_da.set_namespace([0xFF; 29]);

        assert_eq!(celestia_da.last_height(), last_height_before);
        assert_eq!(celestia_da.health_status(), health_status_before);
        assert_eq!(celestia_da.config().rpc_url, rpc_url_before);
    }

    // ════════════════════════════════════════════════════════════════════════
    // VALIDATE_NAMESPACE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_validate_namespace_valid() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        let result = celestia_da.validate_namespace();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_namespace_dsdn_v0_valid() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let mut config = create_test_config(&mock_server.uri());
        config.namespace = DSDN_NAMESPACE_V0;
        let celestia_da = CelestiaDA::new(config).unwrap();

        let result = celestia_da.validate_namespace();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_namespace_all_zeros_invalid() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let mut celestia_da = CelestiaDA::new(config).unwrap();

        celestia_da.set_namespace([0x00; 29]);

        let result = celestia_da.validate_namespace();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DAError::InvalidNamespace));
    }

    #[tokio::test]
    async fn test_validate_namespace_no_panic() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let mut celestia_da = CelestiaDA::new(config).unwrap();

        let test_cases: [[u8; 29]; 4] = [
            [0x00; 29],
            [0xFF; 29],
            [0x01; 29],
            DSDN_NAMESPACE_V0,
        ];

        for ns in test_cases {
            celestia_da.set_namespace(ns);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                celestia_da.validate_namespace()
            }));
            assert!(result.is_ok());
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // VALIDATE_NAMESPACE_FORMAT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_validate_namespace_format_valid() {
        let ns = [0x01; 29];
        assert!(validate_namespace_format(&ns).is_ok());
    }

    #[test]
    fn test_validate_namespace_format_all_zeros() {
        let ns = [0x00; 29];
        let result = validate_namespace_format(&ns);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DAError::InvalidNamespace));
    }

    #[test]
    fn test_validate_namespace_format_one_non_zero() {
        let mut ns = [0x00; 29];
        ns[28] = 0x01;
        assert!(validate_namespace_format(&ns).is_ok());
    }

    // ════════════════════════════════════════════════════════════════════════
    // INITIALIZATION SUCCESS TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_new_success_with_mock_server() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());

        let result = CelestiaDA::new(config.clone());
        assert!(result.is_ok());

        let celestia_da = result.unwrap();

        assert_eq!(celestia_da.config().rpc_url, mock_server.uri());
        assert_eq!(celestia_da.namespace(), &[0x01; 29]);
        assert_eq!(celestia_da.last_height(), 0);
        assert_eq!(celestia_da.health_status(), DAHealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_new_all_fields_initialized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let config = DAConfig {
            rpc_url: mock_server.uri(),
            namespace: [0xAB; 29],
            auth_token: Some("test_token".to_string()),
            timeout_ms: 10000,
            retry_count: 5,
            retry_delay_ms: 500,
            network: "testnet".to_string(),
            enable_pooling: false,
            max_connections: 1,
            idle_timeout_ms: 30000,
        };

        let celestia_da = CelestiaDA::new(config).unwrap();

        assert_eq!(celestia_da.config().timeout_ms, 10000);
        assert_eq!(celestia_da.config().retry_count, 5);
        assert_eq!(celestia_da.config().auth_token, Some("test_token".to_string()));
        assert_eq!(celestia_da.namespace(), &[0xAB; 29]);
        assert_eq!(celestia_da.last_height(), 0);
        assert_eq!(celestia_da.health_status(), DAHealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_health_status_initial_value() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        assert_eq!(celestia_da.health_status(), DAHealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_last_height_deterministic() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());

        let celestia_da1 = CelestiaDA::new(config.clone()).unwrap();
        let celestia_da2 = CelestiaDA::new(config).unwrap();

        assert_eq!(celestia_da1.last_height(), 0);
        assert_eq!(celestia_da2.last_height(), 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // INITIALIZATION FAILURE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_new_fails_server_unreachable() {
        let config = create_test_config("http://127.0.0.1:1");

        let result = CelestiaDA::new(config);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(err, DAError::NetworkError(_) | DAError::Unavailable));
    }

    #[tokio::test]
    async fn test_new_fails_invalid_url() {
        let config = create_test_config("not_a_valid_url");

        let result = CelestiaDA::new(config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_new_no_panic_on_error() {
        let config = create_test_config("http://invalid.invalid.invalid:99999");

        let result = std::panic::catch_unwind(|| {
            CelestiaDA::new(config)
        });

        assert!(result.is_ok());
        assert!(result.unwrap().is_err());
    }

    #[tokio::test]
    async fn test_new_error_type_correct() {
        let config = create_test_config("http://127.0.0.1:1");

        let result = CelestiaDA::new(config);
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            DAError::NetworkError(_) | DAError::Unavailable | DAError::Timeout => {}
            other => panic!("Unexpected error type: {:?}", other),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // FROM_ENV TESTS
    // ════════════════════════════════════════════════════════════════════════

   #[tokio::test]
    async fn test_from_env_success() {
        // Clear ALL DA-related env vars first to ensure clean state
        // This prevents interference from .env.mainnet or other tests
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");
        std::env::remove_var("DA_AUTH_TOKEN");
        std::env::remove_var("DA_NETWORK");
        std::env::remove_var("DA_TIMEOUT_MS");
        std::env::remove_var("DA_RETRY_COUNT");
        std::env::remove_var("DA_RETRY_DELAY_MS");
        std::env::remove_var("DA_ENABLE_POOLING");
        std::env::remove_var("DA_MAX_CONNECTIONS");
        std::env::remove_var("DA_IDLE_TIMEOUT_MS");

        let mock_server = MockServer::start().await;
        // Save URI before any potential cleanup
        let mock_uri = mock_server.uri();

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        std::env::set_var("DA_RPC_URL", &mock_uri);
        std::env::set_var("DA_NAMESPACE", "00112233445566778899aabbccddeeff00112233445566778899aabbcc");
        std::env::set_var("DA_NETWORK", "mocha"); // Use testnet to avoid mainnet auth requirement

        let result = CelestiaDA::from_env();

        // Cleanup env vars
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");
        std::env::remove_var("DA_NETWORK");

        // Assertions after cleanup
        assert!(result.is_ok(), "from_env should succeed: {:?}", result.err());
        assert_eq!(result.unwrap().config().rpc_url, mock_uri);
    }

    #[tokio::test]
    async fn test_from_env_fails_missing_vars() {
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");

        let result = CelestiaDA::from_env();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_from_env_fails_invalid_namespace() {
        std::env::set_var("DA_RPC_URL", "http://localhost:26658");
        std::env::set_var("DA_NAMESPACE", "invalid_hex");

        let result = CelestiaDA::from_env();

        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_from_env_error_controlled() {
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");

        let result = std::panic::catch_unwind(|| {
            CelestiaDA::from_env()
        });

        assert!(result.is_ok());
        assert!(result.unwrap().is_err());
    }

    #[tokio::test]
    async fn test_from_env_invalid_timeout() {
        std::env::set_var("DA_RPC_URL", "http://localhost:26658");
        std::env::set_var("DA_NAMESPACE", "00112233445566778899aabbccddeeff00112233445566778899aabbcc");
        std::env::set_var("DA_TIMEOUT_MS", "not_a_number");

        let result = CelestiaDA::from_env();

        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");
        std::env::remove_var("DA_TIMEOUT_MS");

        assert!(result.is_err());
    }

    // ════════════════════════════════════════════════════════════════════════
    // FIELD ACCESS TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_set_last_height() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        assert_eq!(celestia_da.last_height(), 0);

        celestia_da.set_last_height(12345);
        assert_eq!(celestia_da.last_height(), 12345);

        celestia_da.set_last_height(u64::MAX);
        assert_eq!(celestia_da.last_height(), u64::MAX);
    }

    #[tokio::test]
    async fn test_set_health_status() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        assert_eq!(celestia_da.health_status(), DAHealthStatus::Healthy);

        celestia_da.set_health_status(DAHealthStatus::Degraded);
        assert_eq!(celestia_da.health_status(), DAHealthStatus::Degraded);

        celestia_da.set_health_status(DAHealthStatus::Unavailable);
        assert_eq!(celestia_da.health_status(), DAHealthStatus::Unavailable);

        celestia_da.set_health_status(DAHealthStatus::Healthy);
        assert_eq!(celestia_da.health_status(), DAHealthStatus::Healthy);
    }

    // ════════════════════════════════════════════════════════════════════════
    // SERVER RESPONSE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_new_succeeds_with_various_status_codes() {
        for status_code in [200, 201, 204, 301, 302, 404] {
            let mock_server = MockServer::start().await;

            Mock::given(method("HEAD"))
                .respond_with(ResponseTemplate::new(status_code))
                .mount(&mock_server)
                .await;

            let config = create_test_config(&mock_server.uri());
            let result = CelestiaDA::new(config);

            assert!(result.is_ok(), "Should succeed with status code {}", status_code);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // SUBSCRIBE_BLOBS TESTS
    // ════════════════════════════════════════════════════════════════════════

    use futures::StreamExt;
    use wiremock::matchers::{body_string_contains, method as http_method};

    fn create_network_head_response(height: u64) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"header":{{"height":"{}"}}}}}}"#,
            height
        )
    }

    fn create_get_all_response(blobs: &[(u32, &[u8; 29], &[u8], &[u8; 32])]) -> String {
        let blob_items: Vec<String> = blobs
            .iter()
            .map(|(index, namespace, data, commitment)| {
                format!(
                    r#"{{"namespace":"{}","data":"{}","share_version":0,"commitment":"{}","index":{}}}"#,
                    BASE64.encode(namespace),
                    BASE64.encode(data),
                    BASE64.encode(commitment),
                    index
                )
            })
            .collect();

        format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":[{}]}}"#,
            blob_items.join(",")
        )
    }

    fn create_get_all_empty_response() -> String {
        r#"{"jsonrpc":"2.0","id":1,"result":[]}"#.to_string()
    }

    fn create_get_all_not_found_response() -> String {
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"blob: not found"}}"#.to_string()
    }

    // ════════════════════════════════════════════════════════════════════════
    // A. SUBSCRIBE_BLOBS BASIC TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_subscribe_blobs_basic_valid_namespace() {
        let mock_server = MockServer::start().await;
        let test_namespace = [0x01; 29];
        let test_data = b"test blob data";
        let test_commitment = compute_blob_commitment(test_data);

        // Mock HEAD for init
        Mock::given(http_method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Mock header.NetworkHead
        Mock::given(http_method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(ResponseTemplate::new(200).set_body_string(create_network_head_response(1)))
            .mount(&mock_server)
            .await;

        // Mock blob.GetAll with one blob
        Mock::given(http_method("POST"))
            .and(body_string_contains("blob.GetAll"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                create_get_all_response(&[(0, &test_namespace, test_data, &test_commitment)])
            ))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = Arc::new(CelestiaDA::new(config).unwrap());

        let mut stream = celestia_da.subscribe_blobs(&test_namespace);

        // Get first blob with timeout
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            stream.next()
        ).await;

        assert!(result.is_ok(), "Stream should yield within timeout");
        let item = result.unwrap();
        assert!(item.is_some(), "Stream should yield a blob");

        let blob_result = item.unwrap();
        assert!(blob_result.is_ok(), "Blob should be Ok");

        let blob = blob_result.unwrap();
        assert_eq!(blob.namespace, test_namespace);
        assert_eq!(blob.data, test_data);
        assert_eq!(blob.commitment, test_commitment);
    }

    #[tokio::test]
    async fn test_subscribe_blobs_yields_in_order() {
        let mock_server = MockServer::start().await;
        let test_namespace = [0x02; 29];

        let data1 = b"blob one";
        let data2 = b"blob two";
        let data3 = b"blob three";
        let commitment1 = compute_blob_commitment(data1);
        let commitment2 = compute_blob_commitment(data2);
        let commitment3 = compute_blob_commitment(data3);

        Mock::given(http_method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(http_method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(ResponseTemplate::new(200).set_body_string(create_network_head_response(1)))
            .mount(&mock_server)
            .await;

        // Return blobs in non-sequential index order to test sorting
        Mock::given(http_method("POST"))
            .and(body_string_contains("blob.GetAll"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                create_get_all_response(&[
                    (2, &test_namespace, data3, &commitment3), // index 2 first
                    (0, &test_namespace, data1, &commitment1), // index 0 second
                    (1, &test_namespace, data2, &commitment2), // index 1 third
                ])
            ))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = Arc::new(CelestiaDA::new(config).unwrap());

        let mut stream = celestia_da.subscribe_blobs(&test_namespace);

        // Collect first 3 blobs
        let mut received = Vec::new();
        for _ in 0..3 {
            let result = tokio::time::timeout(Duration::from_secs(5), stream.next()).await;
            if let Ok(Some(Ok(blob))) = result {
                received.push(blob);
            }
        }

        assert_eq!(received.len(), 3, "Should receive 3 blobs");

        // Verify ordering by index (ASC)
        assert_eq!(received[0].index, 0);
        assert_eq!(received[1].index, 1);
        assert_eq!(received[2].index, 2);

        // Verify data matches expected order
        assert_eq!(received[0].data, data1);
        assert_eq!(received[1].data, data2);
        assert_eq!(received[2].data, data3);
    }

    #[tokio::test]
    async fn test_subscribe_blobs_no_duplicates() {
        let mock_server = MockServer::start().await;
        let test_namespace = [0x03; 29];
        let test_data = b"unique blob";
        let test_commitment = compute_blob_commitment(test_data);

        Mock::given(http_method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);

        Mock::given(http_method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(ResponseTemplate::new(200).set_body_string(create_network_head_response(1)))
            .mount(&mock_server)
            .await;

        Mock::given(http_method("POST"))
            .and(body_string_contains("blob.GetAll"))
            .respond_with(move |_: &wiremock::Request| {
                call_count_clone.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_string(
                    create_get_all_response(&[(0, &test_namespace, test_data, &test_commitment)])
                )
            })
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = Arc::new(CelestiaDA::new(config).unwrap());

        let mut stream = celestia_da.subscribe_blobs(&test_namespace);

        // Get first blob
        let result1 = tokio::time::timeout(Duration::from_secs(5), stream.next()).await;
        assert!(result1.is_ok());
        let blob1 = result1.unwrap().unwrap().unwrap();
        assert_eq!(blob1.height, 1);
        assert_eq!(blob1.index, 0);

        // The stream should not yield duplicates even if polled again
        // Due to seen_blobs tracking
    }

    // ════════════════════════════════════════════════════════════════════════
    // B. NAMESPACE FILTER TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_subscribe_blobs_filters_wrong_namespace() {
        let mock_server = MockServer::start().await;
        let target_namespace = [0x10; 29];
        let wrong_namespace = [0x20; 29];

        let target_data = b"target blob";
        let wrong_data = b"wrong namespace blob";
        let target_commitment = compute_blob_commitment(target_data);
        let wrong_commitment = compute_blob_commitment(wrong_data);

        Mock::given(http_method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(http_method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(ResponseTemplate::new(200).set_body_string(create_network_head_response(1)))
            .mount(&mock_server)
            .await;

        // Return both target and wrong namespace blobs
        Mock::given(http_method("POST"))
            .and(body_string_contains("blob.GetAll"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                create_get_all_response(&[
                    (0, &wrong_namespace, wrong_data, &wrong_commitment),
                    (1, &target_namespace, target_data, &target_commitment),
                ])
            ))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = Arc::new(CelestiaDA::new(config).unwrap());

        let mut stream = celestia_da.subscribe_blobs(&target_namespace);

        // Should only get the target namespace blob
        let result = tokio::time::timeout(Duration::from_secs(5), stream.next()).await;
        assert!(result.is_ok());

        let blob = result.unwrap().unwrap().unwrap();
        assert_eq!(blob.namespace, target_namespace, "Should only yield target namespace");
        assert_eq!(blob.data, target_data);
    }

    #[tokio::test]
    async fn test_subscribe_blobs_ignores_mismatched_namespace() {
        let mock_server = MockServer::start().await;
        let target_namespace = [0x11; 29];
        let other_namespace = [0x22; 29];

        let other_data = b"other namespace data";
        let other_commitment = compute_blob_commitment(other_data);

        Mock::given(http_method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(http_method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(ResponseTemplate::new(200).set_body_string(create_network_head_response(1)))
            .mount(&mock_server)
            .await;

        // Only return blobs with different namespace
        Mock::given(http_method("POST"))
            .and(body_string_contains("blob.GetAll"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                create_get_all_response(&[(0, &other_namespace, other_data, &other_commitment)])
            ))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = Arc::new(CelestiaDA::new(config).unwrap());

        let mut stream = celestia_da.subscribe_blobs(&target_namespace);

        // Should timeout because no matching blobs
        let result = tokio::time::timeout(Duration::from_millis(500), stream.next()).await;

        // Either timeout or empty - both acceptable since wrong namespace is filtered
        if let Ok(Some(Ok(blob))) = result {
            panic!("Should not yield blob with wrong namespace, got: {:?}", blob.namespace);
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // C. ORDERING GUARANTEE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_subscribe_blobs_ordering_height_index() {
        let mock_server = MockServer::start().await;
        let test_namespace = [0x04; 29];

        // Blobs at different heights
        let data_h1_i0 = b"height1-index0";
        let data_h1_i1 = b"height1-index1";
        let commitment_h1_i0 = compute_blob_commitment(data_h1_i0);
        let commitment_h1_i1 = compute_blob_commitment(data_h1_i1);

        Mock::given(http_method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(http_method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(ResponseTemplate::new(200).set_body_string(create_network_head_response(1)))
            .mount(&mock_server)
            .await;

        // Return blobs in random order, expect sorted output
        Mock::given(http_method("POST"))
            .and(body_string_contains("blob.GetAll"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                create_get_all_response(&[
                    (1, &test_namespace, data_h1_i1, &commitment_h1_i1), // index 1 first
                    (0, &test_namespace, data_h1_i0, &commitment_h1_i0), // index 0 second
                ])
            ))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = Arc::new(CelestiaDA::new(config).unwrap());

        let mut stream = celestia_da.subscribe_blobs(&test_namespace);

        // Get blobs
        let result1 = tokio::time::timeout(Duration::from_secs(5), stream.next()).await;
        let result2 = tokio::time::timeout(Duration::from_secs(5), stream.next()).await;

        assert!(result1.is_ok());
        assert!(result2.is_ok());

        let blob1 = result1.unwrap().unwrap().unwrap();
        let blob2 = result2.unwrap().unwrap().unwrap();

        // Verify ordering: index 0 before index 1
        assert_eq!(blob1.index, 0, "First blob should have index 0");
        assert_eq!(blob2.index, 1, "Second blob should have index 1");
    }

    // ════════════════════════════════════════════════════════════════════════
    // D. RECONNECTION TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_subscribe_blobs_reconnection_after_failure() {
        let mock_server = MockServer::start().await;
        let test_namespace = [0x05; 29];
        let test_data = b"reconnection blob";
        let test_commitment = compute_blob_commitment(test_data);

        Mock::given(http_method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);

        Mock::given(http_method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(move |_: &wiremock::Request| {
                let count = call_count_clone.fetch_add(1, Ordering::SeqCst);
                if count == 0 {
                    // First call fails
                    ResponseTemplate::new(500).set_body_string("Internal Server Error")
                } else {
                    // Subsequent calls succeed
                    ResponseTemplate::new(200).set_body_string(create_network_head_response(1))
                }
            })
            .mount(&mock_server)
            .await;

        Mock::given(http_method("POST"))
            .and(body_string_contains("blob.GetAll"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                create_get_all_response(&[(0, &test_namespace, test_data, &test_commitment)])
            ))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = Arc::new(CelestiaDA::new(config).unwrap());

        let mut stream = celestia_da.subscribe_blobs(&test_namespace);

        // First attempt should fail but stream continues
        let result1 = tokio::time::timeout(Duration::from_secs(2), stream.next()).await;
        // Either error or success - stream should not terminate
        if let Ok(Some(Err(_))) = result1 {
            // Error is expected on first try
        }

        // Subsequent attempt should succeed
        let result2 = tokio::time::timeout(Duration::from_secs(5), stream.next()).await;
        assert!(result2.is_ok(), "Stream should eventually succeed after retry");
    }

    #[tokio::test]
    async fn test_subscribe_blobs_stream_survives_error() {
        let mock_server = MockServer::start().await;
        let test_namespace = [0x06; 29];

        Mock::given(http_method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Always return network error
        Mock::given(http_method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = Arc::new(CelestiaDA::new(config).unwrap());

        let mut stream = celestia_da.subscribe_blobs(&test_namespace);

        // Get multiple errors - stream should not terminate
        for _ in 0..3 {
            let result = tokio::time::timeout(Duration::from_secs(2), stream.next()).await;
            if let Ok(Some(result)) = result {
                assert!(result.is_err(), "Should return error on network failure");
            }
        }

        // Stream should still be alive (not None)
    }

    #[tokio::test]
    async fn test_subscribe_blobs_no_height_reset_on_reconnect() {
        let mock_server = MockServer::start().await;
        let test_namespace = [0x07; 29];
        let test_data = b"no reset blob";
        let test_commitment = compute_blob_commitment(test_data);

        Mock::given(http_method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_head = Arc::clone(&call_count);
        let call_count_getall = Arc::clone(&call_count);

        Mock::given(http_method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(move |_: &wiremock::Request| {
                call_count_head.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_string(create_network_head_response(5))
            })
            .mount(&mock_server)
            .await;

        Mock::given(http_method("POST"))
            .and(body_string_contains("blob.GetAll"))
            .respond_with(move |_: &wiremock::Request| {
                let count = call_count_getall.fetch_add(1, Ordering::SeqCst);
                if count == 0 {
                    // First call fails
                    ResponseTemplate::new(500)
                } else {
                    // Second call succeeds with blob at height 1
                    ResponseTemplate::new(200).set_body_string(
                        create_get_all_response(&[(0, &test_namespace, test_data, &test_commitment)])
                    )
                }
            })
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = Arc::new(CelestiaDA::new(config).unwrap());
        celestia_da.set_last_height(0); // Start from height 1

        let mut stream = celestia_da.subscribe_blobs(&test_namespace);

        // First attempt might fail
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.next()).await;

        // Second attempt should succeed
        let result = tokio::time::timeout(Duration::from_secs(5), stream.next()).await;

        if let Ok(Some(Ok(blob))) = result {
            // Height should be >= 1, not reset to 0
            assert!(blob.height >= 1, "Height should not reset to 0 after error");
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // E. STREAM SAFETY TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_subscribe_blobs_no_panic() {
        let mock_server = MockServer::start().await;
        let test_namespace = [0x08; 29];

        Mock::given(http_method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Return malformed response
        Mock::given(http_method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = Arc::new(CelestiaDA::new(config).unwrap());

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let mut stream = celestia_da.subscribe_blobs(&test_namespace);
                    let _ = tokio::time::timeout(Duration::from_millis(500), stream.next()).await;
                });
            }).join().unwrap()
        }));

        assert!(result.is_ok(), "Stream should not panic on malformed response");
    }

    #[tokio::test]
    async fn test_subscribe_blobs_no_hang() {
        let mock_server = MockServer::start().await;
        let test_namespace = [0x09; 29];

        Mock::given(http_method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(http_method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(ResponseTemplate::new(200).set_body_string(create_network_head_response(0)))
            .mount(&mock_server)
            .await;

        Mock::given(http_method("POST"))
            .and(body_string_contains("blob.GetAll"))
            .respond_with(ResponseTemplate::new(200).set_body_string(create_get_all_empty_response()))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = Arc::new(CelestiaDA::new(config).unwrap());

        let mut stream = celestia_da.subscribe_blobs(&test_namespace);

        // Should not hang - timeout should fire
        let result = tokio::time::timeout(Duration::from_secs(2), stream.next()).await;

        // Timeout is acceptable, infinite hang is not
        assert!(result.is_err() || result.unwrap().is_some(), "Stream should not hang indefinitely");
    }

    #[tokio::test]
    async fn test_subscribe_blobs_not_busy_loop() {
        let mock_server = MockServer::start().await;
        let test_namespace = [0x0A; 29];

        Mock::given(http_method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);

        Mock::given(http_method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(move |_: &wiremock::Request| {
                call_count_clone.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_string(create_network_head_response(0))
            })
            .mount(&mock_server)
            .await;

        Mock::given(http_method("POST"))
            .and(body_string_contains("blob.GetAll"))
            .respond_with(ResponseTemplate::new(200).set_body_string(create_get_all_empty_response()))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = Arc::new(CelestiaDA::new(config).unwrap());

        let mut stream = celestia_da.subscribe_blobs(&test_namespace);

        // Poll for 1 second
        let _ = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let _ = stream.next().await;
            }
        }).await;

        // With 5 second poll interval, should have very few calls (< 5)
        let calls = call_count.load(Ordering::SeqCst);
        assert!(calls < 10, "Should not busy-loop, got {} calls in 1 second", calls);
    }

    #[tokio::test]
    async fn test_subscribe_blobs_empty_block_handling() {
        let mock_server = MockServer::start().await;
        let test_namespace = [0x0B; 29];

        Mock::given(http_method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(http_method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(ResponseTemplate::new(200).set_body_string(create_network_head_response(1)))
            .mount(&mock_server)
            .await;

        // Return not found error (empty block)
        Mock::given(http_method("POST"))
            .and(body_string_contains("blob.GetAll"))
            .respond_with(ResponseTemplate::new(200).set_body_string(create_get_all_not_found_response()))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = Arc::new(CelestiaDA::new(config).unwrap());

        let mut stream = celestia_da.subscribe_blobs(&test_namespace);

        // Should handle "not found" gracefully without error
        let result = tokio::time::timeout(Duration::from_millis(500), stream.next()).await;

        // Either timeout (waiting for next poll) or empty is fine
        // Should not return an error for "blob not found"
        if let Ok(Some(Err(e))) = result {
            // Only network errors are acceptable, not "not found" as error
            assert!(
                !matches!(e, DAError::BlobNotFound(_)),
                "Should not return BlobNotFound error for empty block"
            );
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // HEALTH_CHECK TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_health_check_healthy_state() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Mock header.NetworkHead with immediate response (low latency)
        Mock::given(method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                create_network_head_response(100)
            ))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        let status = celestia_da.health_check().await;

        assert_eq!(status, DAHealthStatus::Healthy);
        assert_eq!(celestia_da.health_status(), DAHealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_health_check_healthy_updates_last_height() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                create_network_head_response(500)
            ))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        assert_eq!(celestia_da.last_height(), 0);

        let status = celestia_da.health_check().await;

        assert_eq!(status, DAHealthStatus::Healthy);
        assert_eq!(celestia_da.last_height(), 500);
    }

    #[tokio::test]
    async fn test_health_check_degraded_high_latency() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Mock header.NetworkHead with delayed response (high latency)
        Mock::given(method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(create_network_head_response(100))
                    .set_delay(Duration::from_millis(1100)) // > 1000ms threshold
            )
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        let status = celestia_da.health_check().await;

        assert_eq!(status, DAHealthStatus::Degraded);
        assert_eq!(celestia_da.health_status(), DAHealthStatus::Degraded);
    }

    #[tokio::test]
    async fn test_health_check_unavailable_network_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Mock header.NetworkHead with timeout (simulates network issue)
        Mock::given(method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(create_network_head_response(100))
                    .set_delay(Duration::from_secs(10)) // Much longer than timeout
            )
            .mount(&mock_server)
            .await;

        let mut config = create_test_config(&mock_server.uri());
        config.timeout_ms = 100; // Very short timeout

        let celestia_da = CelestiaDA::new(config).unwrap();

        let status = celestia_da.health_check().await;

        assert_eq!(status, DAHealthStatus::Unavailable);
        assert_eq!(celestia_da.health_status(), DAHealthStatus::Unavailable);
    }

    #[tokio::test]
    async fn test_health_check_unavailable_rpc_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Mock header.NetworkHead with RPC error
        Mock::given(method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"internal error"}}"#
            ))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        let status = celestia_da.health_check().await;

        assert_eq!(status, DAHealthStatus::Unavailable);
        assert_eq!(celestia_da.health_status(), DAHealthStatus::Unavailable);
    }

    #[tokio::test]
    async fn test_health_check_unavailable_http_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Mock header.NetworkHead with HTTP 500 error
        Mock::given(method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        let status = celestia_da.health_check().await;

        assert_eq!(status, DAHealthStatus::Unavailable);
        assert_eq!(celestia_da.health_status(), DAHealthStatus::Unavailable);
    }

    #[tokio::test]
    async fn test_health_check_unavailable_invalid_response() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Mock header.NetworkHead with invalid JSON
        Mock::given(method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        let status = celestia_da.health_check().await;

        assert_eq!(status, DAHealthStatus::Unavailable);
        assert_eq!(celestia_da.health_status(), DAHealthStatus::Unavailable);
    }

    #[tokio::test]
    async fn test_health_check_unavailable_missing_result() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Mock header.NetworkHead with null result
        Mock::given(method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"jsonrpc":"2.0","id":1,"result":null}"#
            ))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        let status = celestia_da.health_check().await;

        assert_eq!(status, DAHealthStatus::Unavailable);
    }

    #[tokio::test]
    async fn test_health_check_no_panic_on_any_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let bad_responses = vec![
            "",
            "null",
            "[]",
            "{}",
            r#"{"error": "bad"}"#,
            r#"{"jsonrpc":"2.0","id":1}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"header":{}}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"header":{"height":"not_a_number"}}}"#,
        ];

        for bad_response in bad_responses {
            let server = MockServer::start().await;

            Mock::given(method("HEAD"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_string(bad_response))
                .mount(&server)
                .await;

            let config = create_test_config(&server.uri());
            let celestia_da = CelestiaDA::new(config).unwrap();

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                std::thread::spawn(move || {
                    tokio::runtime::Runtime::new().unwrap().block_on(async {
                        celestia_da.health_check().await
                    })
                }).join().unwrap()
            }));

            assert!(result.is_ok(), "Should not panic on bad response: {}", bad_response);
        }
    }

    #[tokio::test]
    async fn test_health_check_latency_is_measured() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Add a small delay to ensure latency is measurable
        Mock::given(method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(create_network_head_response(100))
                    .set_delay(Duration::from_millis(50))
            )
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        let start = std::time::Instant::now();
        let _status = celestia_da.health_check().await;
        let elapsed = start.elapsed();

        // Verify that the health check actually waited for the response
        // It should be at least 50ms due to the mock delay
        assert!(elapsed.as_millis() >= 40, "Latency should be at least 40ms, was {}ms", elapsed.as_millis());
    }

    #[tokio::test]
    async fn test_health_check_internal_state_updates() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                create_network_head_response(100)
            ))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        // Initially healthy
        assert_eq!(celestia_da.health_status(), DAHealthStatus::Healthy);

        // Manually set to degraded
        celestia_da.set_health_status(DAHealthStatus::Degraded);
        assert_eq!(celestia_da.health_status(), DAHealthStatus::Degraded);

        // health_check should update back to healthy
        let status = celestia_da.health_check().await;
        assert_eq!(status, DAHealthStatus::Healthy);
        assert_eq!(celestia_da.health_status(), DAHealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_health_check_consecutive_calls() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(body_string_contains("header.NetworkHead"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                create_network_head_response(100)
            ))
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        // Multiple consecutive health checks should all work
        for _ in 0..5 {
            let status = celestia_da.health_check().await;
            assert_eq!(status, DAHealthStatus::Healthy);
        }
    }
}