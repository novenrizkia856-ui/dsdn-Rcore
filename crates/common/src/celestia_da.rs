//! Celestia DA Backend Implementation
//!
//! Modul ini menyediakan implementasi konkret `CelestiaDA` sebagai
//! backend Data Availability menggunakan Celestia network.
//!
//! Tahap ini berisi inisialisasi, wiring, manajemen namespace, dan
//! operasi `post_blob` untuk mengirim data ke Celestia.

use crate::da::{BlobRef, DAConfig, DAError, DAHealthStatus};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use sha3::Sha3_256;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Duration;
use tracing::{debug, error, info, warn};

// ════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════

/// Maximum blob size in bytes (2 MB)
pub const MAX_BLOB_SIZE: usize = 2 * 1024 * 1024;

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

/// JSON-RPC request untuk blob.Submit
#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: Vec<serde_json::Value>,
}

/// JSON-RPC response
#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: u64,
    result: Option<u64>,
    error: Option<JsonRpcError>,
}

/// JSON-RPC error
#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
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
        // Use blocking client for initialization
        // This is acceptable during initialization phase
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

        let rpc_response: JsonRpcResponse = serde_json::from_str(&body)
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
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path, body_json_schema};
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
    // POST_BLOB SUCCESS TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_post_blob_success() {
        let mock_server = MockServer::start().await;

        // Mock HEAD for init
        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Mock POST for blob.Submit
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(create_blob_submit_success_response(12345))
            )
            .mount(&mock_server)
            .await;

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        // Initial last_height should be 0
        assert_eq!(celestia_da.last_height(), 0);

        let data = b"test blob data";
        let result = celestia_da.post_blob(data).await;

        assert!(result.is_ok(), "post_blob should succeed");

        let blob_ref = result.unwrap();
        assert_eq!(blob_ref.height, 12345);
        assert_eq!(blob_ref.namespace, [0x01; 29]);
        assert_eq!(blob_ref.commitment, compute_blob_commitment(data));

        // last_height should be updated
        assert_eq!(celestia_da.last_height(), 12345);

        // health status should be Healthy
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

        // Test with 1 byte
        let result = celestia_da.post_blob(&[0x42]).await;
        assert!(result.is_ok());

        // Test with empty (allowed)
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

        assert_eq!(celestia_da.last_height(), 0, "Initial height should be 0");

        let _ = celestia_da.post_blob(b"data").await;

        assert_eq!(celestia_da.last_height(), 999, "Height should be updated after success");
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

        // No POST mock - should not reach network

        let config = create_test_config(&mock_server.uri());
        let celestia_da = CelestiaDA::new(config).unwrap();

        // Create data > 2MB
        let large_data = vec![0u8; MAX_BLOB_SIZE + 1];
        let result = celestia_da.post_blob(&large_data).await;

        assert!(result.is_err(), "Should fail for data > 2MB");
        
        let err = result.unwrap_err();
        match err {
            DAError::Other(msg) => {
                assert!(msg.contains("exceeds maximum"), "Error message should mention size limit");
            }
            _ => panic!("Expected DAError::Other for size validation"),
        }

        // last_height should NOT be updated
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

        // Exactly 2MB should succeed
        let max_data = vec![0u8; MAX_BLOB_SIZE];
        let result = celestia_da.post_blob(&max_data).await;

        assert!(result.is_ok(), "Exactly 2MB should succeed");
    }

    #[tokio::test]
    async fn test_post_blob_no_network_call_on_size_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Counter for POST requests
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

        assert_eq!(call_count.load(Ordering::SeqCst), 0, "No network call should be made for size validation error");
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

        // Track call count
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
                        .set_body_string(create_blob_submit_success_response(777))
                }
            })
            .mount(&mock_server)
            .await;

        let mut config = create_test_config(&mock_server.uri());
        config.retry_count = 3;
        config.retry_delay_ms = 10; // Fast for testing

        let celestia_da = CelestiaDA::new(config).unwrap();
        let result = celestia_da.post_blob(b"retry test").await;

        assert!(result.is_ok(), "Should succeed after retries");
        assert_eq!(call_count.load(Ordering::SeqCst), 3, "Should have made 3 calls (2 failures + 1 success)");
        assert_eq!(celestia_da.last_height(), 777);
    }

    #[tokio::test]
    async fn test_post_blob_all_retries_exhausted() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // All calls fail
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let mut config = create_test_config(&mock_server.uri());
        config.retry_count = 2;
        config.retry_delay_ms = 10;

        let celestia_da = CelestiaDA::new(config).unwrap();
        let result = celestia_da.post_blob(b"fail test").await;

        assert!(result.is_err(), "Should fail after all retries exhausted");
        
        // health status should be Unavailable
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
        config.retry_count = 2; // 1 initial + 2 retries = 3 total
        config.retry_delay_ms = 10;

        let celestia_da = CelestiaDA::new(config).unwrap();
        let _ = celestia_da.post_blob(b"count test").await;

        // Initial + retry_count retries
        assert_eq!(call_count.load(Ordering::SeqCst), 3, "Should make exactly 1 + retry_count calls");
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
        config.retry_count = 0; // No retry for this test

        let celestia_da = CelestiaDA::new(config).unwrap();
        let result = celestia_da.post_blob(b"test").await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DAError::SerializationError(_)));
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
        let err = result.unwrap_err();
        match err {
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
        let err = result.unwrap_err();
        assert!(matches!(err, DAError::SerializationError(_)));
    }

    #[tokio::test]
    async fn test_post_blob_no_panic_on_errors() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Various bad responses
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
            
            // Should not panic
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    celestia_da.post_blob(b"test").await
                })
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
        assert_eq!(ns1, ns2, "Same input should produce same output");
    }

    #[test]
    fn test_compute_namespace_different_inputs() {
        let ns1 = compute_namespace("namespace-a");
        let ns2 = compute_namespace("namespace-b");
        assert_ne!(ns1, ns2, "Different inputs should produce different outputs");
    }

    #[test]
    fn test_compute_namespace_length() {
        let ns = compute_namespace("any-string");
        assert_eq!(ns.len(), 29, "Namespace must be exactly 29 bytes");
    }

    #[test]
    fn test_compute_namespace_empty_string() {
        let ns = compute_namespace("");
        assert_eq!(ns.len(), 29, "Empty string should still produce 29 bytes");
    }

    #[test]
    fn test_compute_namespace_long_string() {
        let long_string = "a".repeat(1000);
        let ns = compute_namespace(&long_string);
        assert_eq!(ns.len(), 29, "Long string should produce 29 bytes");
    }

    #[test]
    fn test_compute_namespace_consistent_across_runs() {
        // This tests that the same input always gives same output
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
        assert_eq!(
            DSDN_NAMESPACE_V0, computed,
            "DSDN_NAMESPACE_V0 must equal compute_namespace(\"dsdn-control-v0\")"
        );
    }

    #[test]
    fn test_dsdn_namespace_v0_length() {
        assert_eq!(DSDN_NAMESPACE_V0.len(), 29);
    }

    #[test]
    fn test_dsdn_namespace_v0_not_all_zeros() {
        let all_zeros = DSDN_NAMESPACE_V0.iter().all(|&b| b == 0);
        assert!(!all_zeros, "DSDN_NAMESPACE_V0 should not be all zeros");
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

        // Set some values
        celestia_da.set_last_height(12345);
        celestia_da.set_health_status(DAHealthStatus::Degraded);

        // Capture state before
        let last_height_before = celestia_da.last_height();
        let health_status_before = celestia_da.health_status();
        let rpc_url_before = celestia_da.config().rpc_url.clone();

        // Change namespace
        celestia_da.set_namespace([0xFF; 29]);

        // Verify other fields unchanged
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

        // Default namespace [0x01; 29] should be valid
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

        // Set namespace to all zeros
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

        // Test various namespaces - none should panic
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
            assert!(result.is_ok(), "validate_namespace should not panic");
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
        ns[28] = 0x01; // One non-zero byte
        assert!(validate_namespace_format(&ns).is_ok());
    }

    // ════════════════════════════════════════════════════════════════════════
    // INITIALIZATION SUCCESS TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_new_success_with_mock_server() {
        // Start mock server
        let mock_server = MockServer::start().await;

        // Setup mock response for HEAD request
        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Create config pointing to mock server
        let config = create_test_config(&mock_server.uri());

        // Create CelestiaDA instance
        let result = CelestiaDA::new(config.clone());
        assert!(result.is_ok(), "CelestiaDA::new should succeed");

        let celestia_da = result.unwrap();

        // Verify all fields are set correctly
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
        };

        let celestia_da = CelestiaDA::new(config).unwrap();

        // Verify config is stored correctly
        assert_eq!(celestia_da.config().timeout_ms, 10000);
        assert_eq!(celestia_da.config().retry_count, 5);
        assert_eq!(celestia_da.config().auth_token, Some("test_token".to_string()));

        // Verify namespace is cached
        assert_eq!(celestia_da.namespace(), &[0xAB; 29]);

        // Verify last_height is deterministic (starts at 0)
        assert_eq!(celestia_da.last_height(), 0);

        // Verify health_status is Healthy after successful init
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

        // Health status should be Healthy after successful initialization
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

        // Create multiple instances
        let celestia_da1 = CelestiaDA::new(config.clone()).unwrap();
        let celestia_da2 = CelestiaDA::new(config).unwrap();

        // last_height should be deterministic (always 0 at init)
        assert_eq!(celestia_da1.last_height(), 0);
        assert_eq!(celestia_da2.last_height(), 0);
    }

    // ════════════════════════════════════════════════════════════════════════
    // INITIALIZATION FAILURE TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_new_fails_server_unreachable() {
        // Use invalid URL that won't connect
        let config = create_test_config("http://127.0.0.1:1");

        let result = CelestiaDA::new(config);
        assert!(result.is_err(), "Should fail when server is unreachable");

        let err = result.unwrap_err();
        // Should be NetworkError or Unavailable
        assert!(
            matches!(err, DAError::NetworkError(_) | DAError::Unavailable),
            "Error should be NetworkError or Unavailable, got: {:?}",
            err
        );
    }

    #[tokio::test]
    async fn test_new_fails_invalid_url() {
        let config = create_test_config("not_a_valid_url");

        let result = CelestiaDA::new(config);
        assert!(result.is_err(), "Should fail with invalid URL");
    }

    #[tokio::test]
    async fn test_new_no_panic_on_error() {
        // This test verifies no panic occurs
        let config = create_test_config("http://invalid.invalid.invalid:99999");

        // Should not panic, only return error
        let result = std::panic::catch_unwind(|| {
            CelestiaDA::new(config)
        });

        assert!(result.is_ok(), "Should not panic");
        assert!(result.unwrap().is_err(), "Should return error");
    }

    #[tokio::test]
    async fn test_new_error_type_correct() {
        let config = create_test_config("http://127.0.0.1:1");

        let result = CelestiaDA::new(config);
        assert!(result.is_err());

        // Error should be DAError variant
        let err = result.unwrap_err();
        match err {
            DAError::NetworkError(_) | DAError::Unavailable | DAError::Timeout => {
                // These are acceptable error types
            }
            other => {
                panic!("Unexpected error type: {:?}", other);
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // FROM_ENV TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_from_env_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        // Set environment variables
        std::env::set_var("DA_RPC_URL", mock_server.uri());
        std::env::set_var("DA_NAMESPACE", "00112233445566778899aabbccddeeff00112233445566778899aabbcc");

        let result = CelestiaDA::from_env();
        
        // Cleanup env vars
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");

        assert!(result.is_ok(), "from_env should succeed with valid env vars");

        let celestia_da = result.unwrap();
        assert_eq!(celestia_da.config().rpc_url, mock_server.uri());
    }

    #[tokio::test]
    async fn test_from_env_fails_missing_vars() {
        // Clear env vars
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");

        let result = CelestiaDA::from_env();
        assert!(result.is_err(), "from_env should fail with missing env vars");
    }

    #[tokio::test]
    async fn test_from_env_fails_invalid_namespace() {
        std::env::set_var("DA_RPC_URL", "http://localhost:26658");
        std::env::set_var("DA_NAMESPACE", "invalid_hex");

        let result = CelestiaDA::from_env();

        // Cleanup
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");

        assert!(result.is_err(), "from_env should fail with invalid namespace");
    }

    #[tokio::test]
    async fn test_from_env_error_controlled() {
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");

        // Should not panic
        let result = std::panic::catch_unwind(|| {
            CelestiaDA::from_env()
        });

        assert!(result.is_ok(), "Should not panic");
        assert!(result.unwrap().is_err(), "Should return error");
    }

    #[tokio::test]
    async fn test_from_env_invalid_timeout() {
        std::env::set_var("DA_RPC_URL", "http://localhost:26658");
        std::env::set_var("DA_NAMESPACE", "00112233445566778899aabbccddeeff00112233445566778899aabbcc");
        std::env::set_var("DA_TIMEOUT_MS", "not_a_number");

        let result = CelestiaDA::from_env();

        // Cleanup
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");
        std::env::remove_var("DA_TIMEOUT_MS");

        assert!(result.is_err(), "from_env should fail with invalid timeout");
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

        // Initial value
        assert_eq!(celestia_da.last_height(), 0);

        // Update height
        celestia_da.set_last_height(12345);
        assert_eq!(celestia_da.last_height(), 12345);

        // Update again
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

        // Initial value
        assert_eq!(celestia_da.health_status(), DAHealthStatus::Healthy);

        // Update status
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
        // Test with different successful status codes
        for status_code in [200, 201, 204, 301, 302, 404] {
            let mock_server = MockServer::start().await;

            Mock::given(method("HEAD"))
                .respond_with(ResponseTemplate::new(status_code))
                .mount(&mock_server)
                .await;

            let config = create_test_config(&mock_server.uri());
            let result = CelestiaDA::new(config);

            // Any response (even 4xx) means server is reachable
            assert!(result.is_ok(), "Should succeed with status code {}", status_code);
        }
    }
}