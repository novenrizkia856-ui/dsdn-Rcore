//! Data Availability Layer Abstraction
//!
//! Modul ini mendefinisikan trait `DALayer` sebagai kontrak abstraksi
//! untuk Data Availability layer dalam sistem DSDN. Trait ini memungkinkan
//! DSDN berinteraksi dengan berbagai backend DA secara seragam tanpa
//! terikat pada implementasi spesifik.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use futures::Stream;
use parking_lot::RwLock;

// ════════════════════════════════════════════════════════════════════════════
// SUPPORTING TYPES
// ════════════════════════════════════════════════════════════════════════════

/// Referensi ke blob yang tersimpan di DA layer.
///
/// `BlobRef` menyimpan informasi yang diperlukan untuk mengidentifikasi
/// dan mengambil kembali blob dari DA layer. Struct ini bersifat
/// immutable setelah dibuat.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlobRef {
    /// Height di mana blob di-commit ke DA layer
    pub height: u64,
    /// Commitment hash 32-byte dari blob
    pub commitment: [u8; 32],
    /// Namespace 29-byte tempat blob disimpan
    pub namespace: [u8; 29],
}

/// Data blob yang diterima dari DA layer.
///
/// `Blob` merepresentasikan unit data yang disimpan dan diambil
/// dari DA layer, beserta referensi untuk identifikasi dan
/// timestamp penerimaan.
#[derive(Debug, Clone)]
pub struct Blob {
    /// Referensi ke blob ini di DA layer
    pub ref_: BlobRef,
    /// Data mentah blob
    pub data: Vec<u8>,
    /// Timestamp Unix (milliseconds) saat blob diterima
    pub received_at: u64,
}

// ════════════════════════════════════════════════════════════════════════════
// DA METRICS
// ════════════════════════════════════════════════════════════════════════════

/// Metrics for DA layer operations.
///
/// Tracks latency and request counts for monitoring and observability.
/// All fields are thread-safe and can be accessed concurrently.
#[derive(Debug)]
pub struct DAMetrics {
    /// Total number of post_blob operations
    pub post_count: AtomicU64,
    /// Total number of get_blob operations
    pub get_count: AtomicU64,
    /// Total number of subscribe operations
    pub subscribe_count: AtomicU64,
    /// Total number of health_check operations
    pub health_check_count: AtomicU64,
    /// Cumulative post_blob latency in microseconds
    pub post_latency_us: AtomicU64,
    /// Cumulative get_blob latency in microseconds
    pub get_latency_us: AtomicU64,
    /// Number of failed operations
    pub error_count: AtomicU64,
    /// Number of retry attempts
    pub retry_count: AtomicU64,
    /// Number of successful reconnections
    pub reconnect_count: AtomicU64,
    /// Last operation timestamp (Unix ms)
    pub last_operation_ms: AtomicU64,
}

impl DAMetrics {
    /// Create new metrics with all counters at zero.
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

    /// Record a post_blob operation with latency.
    pub fn record_post(&self, latency: std::time::Duration) {
        self.post_count.fetch_add(1, Ordering::Relaxed);
        self.post_latency_us.fetch_add(latency.as_micros() as u64, Ordering::Relaxed);
        self.update_last_operation();
    }

    /// Record a get_blob operation with latency.
    pub fn record_get(&self, latency: std::time::Duration) {
        self.get_count.fetch_add(1, Ordering::Relaxed);
        self.get_latency_us.fetch_add(latency.as_micros() as u64, Ordering::Relaxed);
        self.update_last_operation();
    }

    /// Record an error.
    pub fn record_error(&self) {
        self.error_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a retry attempt.
    pub fn record_retry(&self) {
        self.retry_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a successful reconnection.
    pub fn record_reconnect(&self) {
        self.reconnect_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a health check.
    pub fn record_health_check(&self) {
        self.health_check_count.fetch_add(1, Ordering::Relaxed);
        self.update_last_operation();
    }

    /// Record a subscribe operation.
    pub fn record_subscribe(&self) {
        self.subscribe_count.fetch_add(1, Ordering::Relaxed);
        self.update_last_operation();
    }

    /// Update last operation timestamp.
    fn update_last_operation(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.last_operation_ms.store(now, Ordering::Relaxed);
    }

    /// Get average post latency in microseconds.
    /// Returns 0 if no posts have been made.
    pub fn avg_post_latency_us(&self) -> u64 {
        let count = self.post_count.load(Ordering::Relaxed);
        if count == 0 {
            return 0;
        }
        self.post_latency_us.load(Ordering::Relaxed) / count
    }

    /// Get average get latency in microseconds.
    /// Returns 0 if no gets have been made.
    pub fn avg_get_latency_us(&self) -> u64 {
        let count = self.get_count.load(Ordering::Relaxed);
        if count == 0 {
            return 0;
        }
        self.get_latency_us.load(Ordering::Relaxed) / count
    }

    /// Get snapshot of all metrics as a struct.
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

/// Snapshot of DA metrics at a point in time.
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

// ════════════════════════════════════════════════════════════════════════════
// DA CONFIG
// ════════════════════════════════════════════════════════════════════════════

/// Konfigurasi untuk DA layer backend.
///
/// `DAConfig` menyimpan semua parameter yang diperlukan untuk
/// menginisialisasi dan berkomunikasi dengan DA layer backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DAConfig {
    /// URL RPC endpoint untuk DA layer
    pub rpc_url: String,
    /// Namespace 29-byte untuk blob storage
    pub namespace: [u8; 29],
    /// Token autentikasi (REQUIRED for mainnet)
    pub auth_token: Option<String>,
    /// Timeout untuk operasi dalam milliseconds
    pub timeout_ms: u64,
    /// Jumlah retry untuk operasi yang gagal
    pub retry_count: u8,
    /// Delay antar retry dalam milliseconds
    pub retry_delay_ms: u64,
    /// Network identifier (mainnet, mocha, arabica, local)
    pub network: String,
    /// Enable connection pooling
    pub enable_pooling: bool,
    /// Maximum concurrent connections
    pub max_connections: u16,
    /// Idle connection timeout in milliseconds
    pub idle_timeout_ms: u64,
}

impl Default for DAConfig {
    /// Membuat DAConfig dengan nilai default yang aman untuk LOCAL DEVELOPMENT ONLY.
    ///
    /// WARNING: These defaults are for local development only.
    /// Production MUST use from_env() with proper credentials.
    ///
    /// Default values:
    /// - `rpc_url`: "http://localhost:26658" (localhost development)
    /// - `namespace`: 29 zero bytes
    /// - `auth_token`: None
    /// - `timeout_ms`: 30000 (30 detik)
    /// - `retry_count`: 3
    /// - `retry_delay_ms`: 1000 (1 detik)
    /// - `network`: "local"
    /// - `enable_pooling`: true
    /// - `max_connections`: 10
    /// - `idle_timeout_ms`: 60000 (60 detik)
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
    /// Membuat DAConfig dari environment variables.
    ///
    /// Environment variables yang dibaca:
    /// - `DA_RPC_URL`: URL RPC endpoint (REQUIRED)
    /// - `DA_NAMESPACE`: Namespace hex string 58 karakter (REQUIRED)
    /// - `DA_AUTH_TOKEN`: Token autentikasi (REQUIRED for mainnet)
    /// - `DA_TIMEOUT_MS`: Timeout dalam milliseconds (default: 30000)
    /// - `DA_RETRY_COUNT`: Jumlah retry (default: 3)
    /// - `DA_RETRY_DELAY_MS`: Delay antar retry dalam ms (default: 1000)
    /// - `DA_NETWORK`: Network identifier (default: "mainnet")
    /// - `DA_ENABLE_POOLING`: Enable connection pooling (default: true)
    /// - `DA_MAX_CONNECTIONS`: Max concurrent connections (default: 10)
    /// - `DA_IDLE_TIMEOUT_MS`: Idle connection timeout (default: 60000)
    ///
    /// # Returns
    ///
    /// * `Ok(DAConfig)` - Konfigurasi berhasil dibaca
    /// * `Err(DAError)` - Error jika environment variable tidak valid
    ///
    /// # Errors
    ///
    /// Mengembalikan error jika:
    /// - `DA_RPC_URL` tidak ada
    /// - `DA_NAMESPACE` tidak ada atau bukan hex valid 58 karakter
    /// - `DA_AUTH_TOKEN` tidak ada untuk network mainnet
    /// - Nilai numerik tidak dapat di-parse
    pub fn from_env() -> Result<Self, DAError> {
        // Required: DA_RPC_URL
        let rpc_url = std::env::var("DA_RPC_URL")
            .map_err(|_| DAError::Other("DA_RPC_URL environment variable not set".to_string()))?;

        // Required: DA_NAMESPACE (hex string, 29 bytes = 58 hex chars)
        let namespace_hex = std::env::var("DA_NAMESPACE")
            .map_err(|_| DAError::Other("DA_NAMESPACE environment variable not set".to_string()))?;
        
        let namespace = Self::parse_namespace(&namespace_hex)?;

        // Optional: DA_AUTH_TOKEN (but REQUIRED for mainnet)
        let auth_token = std::env::var("DA_AUTH_TOKEN").ok();

        // Optional with default: DA_TIMEOUT_MS
        let timeout_ms = match std::env::var("DA_TIMEOUT_MS") {
            Ok(val) => val.parse::<u64>().map_err(|_| {
                DAError::Other(format!("DA_TIMEOUT_MS invalid: '{}'", val))
            })?,
            Err(_) => 30000,
        };

        // Optional with default: DA_RETRY_COUNT
        let retry_count = match std::env::var("DA_RETRY_COUNT") {
            Ok(val) => val.parse::<u8>().map_err(|_| {
                DAError::Other(format!("DA_RETRY_COUNT invalid: '{}'", val))
            })?,
            Err(_) => 3,
        };

        // Optional with default: DA_RETRY_DELAY_MS
        let retry_delay_ms = match std::env::var("DA_RETRY_DELAY_MS") {
            Ok(val) => val.parse::<u64>().map_err(|_| {
                DAError::Other(format!("DA_RETRY_DELAY_MS invalid: '{}'", val))
            })?,
            Err(_) => 1000,
        };

        // Optional with default: DA_NETWORK
        let network = std::env::var("DA_NETWORK").unwrap_or_else(|_| "mainnet".to_string());

        // Validate: auth_token is REQUIRED for mainnet
        if network == "mainnet" && auth_token.is_none() {
            return Err(DAError::Other(
                "DA_AUTH_TOKEN is required for mainnet network".to_string()
            ));
        }

        // Optional with default: DA_ENABLE_POOLING
        let enable_pooling = match std::env::var("DA_ENABLE_POOLING") {
            Ok(val) => val.to_lowercase() == "true" || val == "1",
            Err(_) => true,
        };

        // Optional with default: DA_MAX_CONNECTIONS
        let max_connections = match std::env::var("DA_MAX_CONNECTIONS") {
            Ok(val) => val.parse::<u16>().map_err(|_| {
                DAError::Other(format!("DA_MAX_CONNECTIONS invalid: '{}'", val))
            })?,
            Err(_) => 10,
        };

        // Optional with default: DA_IDLE_TIMEOUT_MS
        let idle_timeout_ms = match std::env::var("DA_IDLE_TIMEOUT_MS") {
            Ok(val) => val.parse::<u64>().map_err(|_| {
                DAError::Other(format!("DA_IDLE_TIMEOUT_MS invalid: '{}'", val))
            })?,
            Err(_) => 60000,
        };

        Ok(Self {
            rpc_url,
            namespace,
            auth_token,
            timeout_ms,
            retry_count,
            retry_delay_ms,
            network,
            enable_pooling,
            max_connections,
            idle_timeout_ms,
        })
    }

    /// Check if this config is for mainnet.
    pub fn is_mainnet(&self) -> bool {
        self.network == "mainnet"
    }

    /// Validate configuration for production use.
    ///
    /// Returns error if configuration is not suitable for production.
    pub fn validate_for_production(&self) -> Result<(), DAError> {
        if self.is_mainnet() {
            if self.auth_token.is_none() {
                return Err(DAError::Other(
                    "auth_token is required for mainnet".to_string()
                ));
            }
            if self.rpc_url.contains("localhost") || self.rpc_url.contains("127.0.0.1") {
                return Err(DAError::Other(
                    "localhost RPC URL not allowed for mainnet".to_string()
                ));
            }
        }
        Ok(())
    }

    /// Parse namespace dari hex string.
    ///
    /// # Arguments
    ///
    /// * `hex` - Hex string 58 karakter (29 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok([u8; 29])` - Namespace bytes
    /// * `Err(DAError)` - Jika hex tidak valid atau panjang salah
    fn parse_namespace(hex: &str) -> Result<[u8; 29], DAError> {
        // Namespace harus 29 bytes = 58 hex chars
        if hex.len() != 58 {
            return Err(DAError::Other(format!(
                "DA_NAMESPACE must be 58 hex characters (29 bytes), got {} characters",
                hex.len()
            )));
        }

        let bytes = Self::hex_to_bytes(hex).map_err(|e| {
            DAError::Other(format!("DA_NAMESPACE invalid hex: {}", e))
        })?;

        let mut namespace = [0u8; 29];
        namespace.copy_from_slice(&bytes);
        Ok(namespace)
    }

    /// Convert hex string to bytes.
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

/// Status kesehatan DA layer.
///
/// Digunakan untuk monitoring dan health checking koneksi ke DA layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DAHealthStatus {
    /// DA layer beroperasi normal, semua operasi berjalan lancar
    Healthy,
    /// DA layer mengalami degradasi performa namun masih beroperasi
    Degraded,
    /// DA layer tidak tersedia atau tidak dapat dijangkau
    Unavailable,
}

/// Error yang dapat terjadi pada operasi DA layer.
///
/// Enum ini mencakup semua kemungkinan error yang dapat terjadi
/// saat berinteraksi dengan DA layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DAError {
    /// Blob dengan referensi yang diberikan tidak ditemukan.
    /// Menyimpan `BlobRef` yang dicari untuk keperluan diagnostik.
    BlobNotFound(BlobRef),
    
    /// Blob ditemukan tetapi data tidak valid.
    /// Terjadi ketika commitment tidak cocok dengan data yang diterima,
    /// mengindikasikan data korupsi atau blob yang salah.
    InvalidBlob,
    
    /// Namespace yang diberikan tidak valid atau tidak cocok.
    InvalidNamespace,
    
    /// Error saat serialisasi atau deserialisasi data.
    /// Biasanya terjadi karena format data yang tidak sesuai.
    SerializationError(String),
    
    /// Error jaringan saat berkomunikasi dengan DA layer.
    /// Termasuk connection refused, DNS failure, dll.
    NetworkError(String),
    
    /// Operasi timeout sebelum selesai.
    Timeout,
    
    /// DA layer tidak tersedia.
    Unavailable,
    
    /// Error autentikasi - token tidak valid atau expired.
    AuthError(String),
    
    /// Error lain yang tidak tercakup dalam kategori di atas.
    Other(String),
}

impl std::fmt::Display for DAError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DAError::BlobNotFound(r) => write!(f, "blob not found at height {}", r.height),
            DAError::InvalidBlob => write!(f, "invalid blob data"),
            DAError::InvalidNamespace => write!(f, "invalid namespace"),
            DAError::SerializationError(msg) => write!(f, "serialization error: {}", msg),
            DAError::NetworkError(msg) => write!(f, "network error: {}", msg),
            DAError::Timeout => write!(f, "operation timeout"),
            DAError::Unavailable => write!(f, "DA layer unavailable"),
            DAError::AuthError(msg) => write!(f, "auth error: {}", msg),
            DAError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for DAError {}

// ════════════════════════════════════════════════════════════════════════════
// TYPE ALIASES
// ════════════════════════════════════════════════════════════════════════════

/// Type alias untuk stream blob dari DA layer.
pub type BlobStream = Pin<Box<dyn Stream<Item = Result<Blob, DAError>> + Send>>;

/// Type alias untuk future hasil blob get.
pub type BlobFuture = Pin<Box<dyn Future<Output = Result<Vec<u8>, DAError>> + Send>>;

// ════════════════════════════════════════════════════════════════════════════
// DA LAYER TRAIT
// ════════════════════════════════════════════════════════════════════════════

/// Trait abstraksi untuk Data Availability layer.
///
/// `DALayer` mendefinisikan kontrak yang harus dipenuhi oleh setiap
/// implementasi DA backend. Trait ini memungkinkan DSDN untuk
/// beroperasi dengan berbagai DA layer secara seragam.
///
/// # Implementors
///
/// - `CelestiaDA`: Implementasi untuk Celestia network
/// - `MockDA`: Implementasi mock untuk testing
///
/// # Thread Safety
///
/// Trait ini memerlukan `Send + Sync` karena instance akan di-share
/// antar async tasks dan threads.
///
/// # Example
///
/// ```ignore
/// use dsdn_common::da::{DALayer, DAConfig, BlobRef};
///
/// async fn use_da(da: &dyn DALayer) {
///     // Post blob
///     let blob_ref = da.post_blob(b"hello").await?;
///     
///     // Get blob
///     let data = da.get_blob(&blob_ref).await?;
///     
///     // Health check
///     let status = da.health_check().await?;
/// }
/// ```
pub trait DALayer: Send + Sync {
    /// Mengirim blob ke DA layer.
    ///
    /// # Arguments
    ///
    /// * `data` - Data blob mentah untuk disimpan
    ///
    /// # Returns
    ///
    /// * `Ok(BlobRef)` - Referensi ke blob yang tersimpan
    /// * `Err(DAError)` - Error jika pengiriman gagal
    fn post_blob(
        &self,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<BlobRef, DAError>> + Send + '_>>;

    /// Mengambil blob dari DA layer.
    ///
    /// # Arguments
    ///
    /// * `ref_` - Referensi ke blob yang akan diambil
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Data blob mentah
    /// * `Err(DAError)` - Error jika pengambilan gagal
    fn get_blob(
        &self,
        ref_: &BlobRef,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DAError>> + Send + '_>>;

    /// Subscribe ke blob stream dari DA layer.
    ///
    /// # Arguments
    ///
    /// * `from_height` - Optional height untuk memulai subscription
    ///
    /// # Returns
    ///
    /// * `Ok(BlobStream)` - Stream blob yang dapat di-poll
    /// * `Err(DAError)` - Error jika subscription gagal
    fn subscribe_blobs(
        &self,
        from_height: Option<u64>,
    ) -> Pin<Box<dyn Future<Output = Result<BlobStream, DAError>> + Send + '_>>;

    /// Melakukan health check pada DA layer.
    ///
    /// # Returns
    ///
    /// * `Ok(DAHealthStatus)` - Status kesehatan DA layer
    /// * `Err(DAError)` - Error jika health check gagal
    fn health_check(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<DAHealthStatus, DAError>> + Send + '_>>;

    /// Get current metrics.
    ///
    /// Returns None if metrics are not available.
    fn metrics(&self) -> Option<DAMetricsSnapshot> {
        None
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ════════════════════════════════════════════════════════════════════════
    // BLOBREF TESTS
    // ════════════════════════════════════════════════════════════════════════

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

    // ════════════════════════════════════════════════════════════════════════
    // DAMETRICS TESTS
    // ════════════════════════════════════════════════════════════════════════

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
        
        // Record multiple operations
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

    // ════════════════════════════════════════════════════════════════════════
    // DACONFIG TESTS
    // ════════════════════════════════════════════════════════════════════════

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
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");

        let result = DAConfig::from_env();
        assert!(result.is_err());
    }

    #[test]
    fn test_daconfig_from_env_missing_namespace() {
        std::env::set_var("DA_RPC_URL", "http://test:1234");
        std::env::remove_var("DA_NAMESPACE");

        let result = DAConfig::from_env();
        assert!(result.is_err());

        // Cleanup
        std::env::remove_var("DA_RPC_URL");
    }

    #[test]
    fn test_daconfig_from_env_invalid_namespace_length() {
        std::env::set_var("DA_RPC_URL", "http://test:1234");
        std::env::set_var("DA_NAMESPACE", "0011223344"); // Too short

        let result = DAConfig::from_env();
        assert!(result.is_err());

        let err = result.unwrap_err();
        if let DAError::Other(msg) = err {
            assert!(msg.contains("58 hex characters"));
        } else {
            panic!("Expected DAError::Other");
        }

        // Cleanup
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");
    }

    #[test]
    fn test_daconfig_from_env_mainnet_requires_auth() {
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

        // Cleanup
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");
        std::env::remove_var("DA_NETWORK");
    }

    #[test]
    fn test_daconfig_from_env_success_local() {
        std::env::set_var("DA_RPC_URL", "http://celestia:26658");
        std::env::set_var("DA_NAMESPACE", "00112233445566778899aabbccddeeff00112233445566778899aabbcc");
        std::env::set_var("DA_NETWORK", "local");
        std::env::remove_var("DA_AUTH_TOKEN");

        let result = DAConfig::from_env();
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.network, "local");
        assert!(config.auth_token.is_none());

        // Cleanup
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");
        std::env::remove_var("DA_NETWORK");
    }

    #[test]
    fn test_daconfig_from_env_success_mainnet() {
        std::env::set_var("DA_RPC_URL", "http://celestia:26658");
        std::env::set_var("DA_NAMESPACE", "00112233445566778899aabbccddeeff00112233445566778899aabbcc");
        std::env::set_var("DA_AUTH_TOKEN", "secret_token_123");
        std::env::set_var("DA_NETWORK", "mainnet");

        let result = DAConfig::from_env();
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.rpc_url, "http://celestia:26658");
        assert_eq!(config.auth_token, Some("secret_token_123".to_string()));
        assert!(config.is_mainnet());

        // Cleanup
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");
        std::env::remove_var("DA_AUTH_TOKEN");
        std::env::remove_var("DA_NETWORK");
    }

    #[test]
    fn test_daconfig_validate_for_production_mainnet_localhost() {
        let config = DAConfig {
            rpc_url: "http://localhost:26658".to_string(),
            namespace: [0u8; 29],
            auth_token: Some("token".to_string()),
            network: "mainnet".to_string(),
            ..Default::default()
        };

        let result = config.validate_for_production();
        assert!(result.is_err());
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

    // ════════════════════════════════════════════════════════════════════════
    // DAERROR TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_daerror_display() {
        let errors = vec![
            (DAError::InvalidBlob, "invalid blob data"),
            (DAError::InvalidNamespace, "invalid namespace"),
            (DAError::Timeout, "operation timeout"),
            (DAError::Unavailable, "DA layer unavailable"),
            (DAError::AuthError("bad token".to_string()), "auth error: bad token"),
            (DAError::NetworkError("conn refused".to_string()), "network error: conn refused"),
        ];

        for (err, expected) in errors {
            assert!(err.to_string().contains(expected));
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // BLOB TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_blob_creation() {
        let blob_ref = BlobRef {
            height: 100,
            commitment: [0x11; 32],
            namespace: [0x22; 29],
        };

        let blob = Blob {
            ref_: blob_ref.clone(),
            data: vec![1, 2, 3, 4, 5],
            received_at: 1234567890,
        };

        assert_eq!(blob.ref_, blob_ref);
        assert_eq!(blob.data, vec![1, 2, 3, 4, 5]);
        assert_eq!(blob.received_at, 1234567890);
    }
}