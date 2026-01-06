//! Celestia DA Backend Implementation
//!
//! Modul ini menyediakan implementasi konkret `CelestiaDA` sebagai
//! backend Data Availability menggunakan Celestia network.
//!
//! Tahap ini HANYA berisi inisialisasi dan wiring.
//! Implementasi trait `DALayer` akan ditambahkan di tahap selanjutnya.

use crate::da::{DAConfig, DAError, DAHealthStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Duration;

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

    /// Mendapatkan referensi ke konfigurasi.
    pub fn config(&self) -> &DAConfig {
        &self.config
    }

    /// Mendapatkan namespace yang digunakan.
    pub fn namespace(&self) -> &[u8; 29] {
        &self.namespace
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
    use wiremock::matchers::method;

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