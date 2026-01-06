//! Celestia DA Backend Implementation
//!
//! Modul ini menyediakan implementasi konkret `CelestiaDA` sebagai
//! backend Data Availability menggunakan Celestia network.
//!
//! Tahap ini berisi inisialisasi, wiring, dan manajemen namespace.
//! Implementasi trait `DALayer` akan ditambahkan di tahap selanjutnya.

use crate::da::{DAConfig, DAError, DAHealthStatus};
use sha2::{Sha256, Digest};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Duration;

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