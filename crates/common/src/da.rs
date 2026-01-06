//! Data Availability Layer Abstraction
//!
//! Modul ini mendefinisikan trait `DALayer` sebagai kontrak abstraksi
//! untuk Data Availability layer dalam sistem DSDN. Trait ini memungkinkan
//! DSDN berinteraksi dengan berbagai backend DA secara seragam tanpa
//! terikat pada implementasi spesifik.

use std::pin::Pin;
use futures::Stream;

// ════════════════════════════════════════════════════════════════════════════
// SUPPORTING TYPES
// ════════════════════════════════════════════════════════════════════════════

/// Referensi ke blob yang tersimpan di DA layer.
///
/// `BlobRef` menyimpan informasi yang diperlukan untuk mengidentifikasi
/// dan mengambil kembali blob dari DA layer. Struct ini bersifat
/// immutable setelah dibuat.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Token autentikasi opsional
    pub auth_token: Option<String>,
    /// Timeout untuk operasi dalam milliseconds
    pub timeout_ms: u64,
    /// Jumlah retry untuk operasi yang gagal
    pub retry_count: u8,
    /// Delay antar retry dalam milliseconds
    pub retry_delay_ms: u64,
}

impl Default for DAConfig {
    /// Membuat DAConfig dengan nilai default yang aman.
    ///
    /// Default values:
    /// - `rpc_url`: "http://localhost:26658" (localhost development)
    /// - `namespace`: 29 zero bytes
    /// - `auth_token`: None
    /// - `timeout_ms`: 30000 (30 detik)
    /// - `retry_count`: 3
    /// - `retry_delay_ms`: 1000 (1 detik)
    fn default() -> Self {
        Self {
            rpc_url: "http://localhost:26658".to_string(),
            namespace: [0u8; 29],
            auth_token: None,
            timeout_ms: 30000,
            retry_count: 3,
            retry_delay_ms: 1000,
        }
    }
}

impl DAConfig {
    /// Membuat DAConfig dari environment variables.
    ///
    /// Environment variables yang dibaca:
    /// - `DA_RPC_URL`: URL RPC endpoint (wajib)
    /// - `DA_NAMESPACE`: Namespace hex string 58 karakter (wajib)
    /// - `DA_AUTH_TOKEN`: Token autentikasi (opsional)
    /// - `DA_TIMEOUT_MS`: Timeout dalam milliseconds (default: 30000)
    /// - `DA_RETRY_COUNT`: Jumlah retry (default: 3)
    /// - `DA_RETRY_DELAY_MS`: Delay antar retry dalam ms (default: 1000)
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
    /// - Nilai numerik tidak dapat di-parse
    pub fn from_env() -> Result<Self, DAError> {
        // Required: DA_RPC_URL
        let rpc_url = std::env::var("DA_RPC_URL")
            .map_err(|_| DAError::Other("DA_RPC_URL environment variable not set".to_string()))?;

        // Required: DA_NAMESPACE (hex string, 29 bytes = 58 hex chars)
        let namespace_hex = std::env::var("DA_NAMESPACE")
            .map_err(|_| DAError::Other("DA_NAMESPACE environment variable not set".to_string()))?;
        
        let namespace = Self::parse_namespace(&namespace_hex)?;

        // Optional: DA_AUTH_TOKEN
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

        Ok(Self {
            rpc_url,
            namespace,
            auth_token,
            timeout_ms,
            retry_count,
            retry_delay_ms,
        })
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
    /// Blob dengan referensi yang diberikan tidak ditemukan
    BlobNotFound,
    /// Timeout saat berkomunikasi dengan DA layer
    Timeout,
    /// Error jaringan saat berkomunikasi dengan DA layer
    NetworkError(String),
    /// Error serialisasi atau deserialisasi data
    SerializationError(String),
    /// Namespace yang diberikan tidak valid
    InvalidNamespace,
    /// DA layer tidak tersedia
    Unavailable,
    /// Error lainnya yang tidak terkategorikan
    Other(String),
}

impl std::fmt::Display for DAError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DAError::BlobNotFound => write!(f, "blob not found"),
            DAError::Timeout => write!(f, "operation timed out"),
            DAError::NetworkError(msg) => write!(f, "network error: {}", msg),
            DAError::SerializationError(msg) => write!(f, "serialization error: {}", msg),
            DAError::InvalidNamespace => write!(f, "invalid namespace"),
            DAError::Unavailable => write!(f, "DA layer unavailable"),
            DAError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for DAError {}

// ════════════════════════════════════════════════════════════════════════════
// TYPE ALIAS
// ════════════════════════════════════════════════════════════════════════════

/// Stream of blobs dari DA layer.
///
/// Type alias ini mendefinisikan stream asinkron yang menghasilkan
/// blob dari DA layer. Stream bersifat `Send` sehingga dapat digunakan
/// dalam konteks async multi-threaded.
///
/// Item stream adalah `Result<Blob, DAError>` untuk mengakomodasi
/// error yang mungkin terjadi selama streaming.
pub type BlobStream = Pin<Box<dyn Stream<Item = Result<Blob, DAError>> + Send>>;

// ════════════════════════════════════════════════════════════════════════════
// DA LAYER TRAIT
// ════════════════════════════════════════════════════════════════════════════

/// Trait abstraksi untuk Data Availability layer.
///
/// `DALayer` mendefinisikan kontrak yang harus dipatuhi oleh implementasi
/// DA layer manapun dalam sistem DSDN. Trait ini memungkinkan DSDN
/// untuk berinteraksi dengan berbagai backend DA secara seragam.
///
/// # Peran dalam DSDN
///
/// DA layer bertugas menyimpan data secara permanen dan memastikan
/// ketersediaan data tersebut. Dalam konteks DSDN, DA layer digunakan
/// untuk menyimpan control-plane state seperti:
/// - Receipt batches dari Coordinator
/// - Validator set updates
/// - Configuration updates
/// - State checkpoints
///
/// # Kontrak untuk Implementor
///
/// Implementor trait ini WAJIB:
/// - Thread-safe (`Send + Sync`)
/// - Mengembalikan error yang sesuai untuk setiap kondisi error
/// - Tidak melakukan blocking pada method async
/// - Menjamin konsistensi antara data yang di-post dan di-get
/// - Menangani reconnection secara internal jika diperlukan
///
/// # Thread Safety
///
/// Trait ini memerlukan `Send + Sync` bound, memastikan implementasi
/// dapat digunakan secara aman dari multiple threads dan dapat
/// di-share antar async tasks.
pub trait DALayer: Send + Sync {
    /// Mengirim blob ke DA layer.
    ///
    /// Method ini menyimpan data mentah ke DA layer dan mengembalikan
    /// referensi (`BlobRef`) yang dapat digunakan untuk mengambil
    /// kembali data tersebut di kemudian hari.
    ///
    /// # Arguments
    ///
    /// * `data` - Slice byte data mentah yang akan disimpan sebagai blob.
    ///   Data tidak dimodifikasi dan disimpan apa adanya.
    ///
    /// # Returns
    ///
    /// * `Ok(BlobRef)` - Referensi ke blob yang berhasil tersimpan,
    ///   berisi height, commitment, dan namespace.
    /// * `Err(DAError)` - Error jika penyimpanan gagal.
    ///
    /// # Errors
    ///
    /// Mengembalikan error jika:
    /// - DA layer tidak tersedia (`DAError::Unavailable`)
    /// - Timeout menunggu konfirmasi (`DAError::Timeout`)
    /// - Error jaringan (`DAError::NetworkError`)
    /// - Error serialisasi data (`DAError::SerializationError`)
    ///
    /// # Async Behavior
    ///
    /// Method ini async dan non-blocking. Future akan resolve setelah
    /// blob terkonfirmasi tersimpan di DA layer. Caller harus await
    /// hingga konfirmasi diterima.
    ///
    /// # Catatan
    ///
    /// Method ini TIDAK melakukan validasi terhadap isi data.
    /// Validasi semantik adalah tanggung jawab caller.
    fn post_blob(&self, data: &[u8]) -> impl std::future::Future<Output = Result<BlobRef, DAError>> + Send;

    /// Mengambil blob dari DA layer berdasarkan referensi.
    ///
    /// Method ini mengambil data blob yang sebelumnya disimpan
    /// menggunakan `post_blob`. Data yang dikembalikan identik
    /// dengan data yang di-post.
    ///
    /// # Arguments
    ///
    /// * `blob_ref` - Referensi ke blob yang akan diambil.
    ///   Harus merupakan `BlobRef` valid yang diperoleh dari `post_blob`.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Data mentah blob yang identik dengan
    ///   data yang di-post sebelumnya.
    /// * `Err(DAError)` - Error jika pengambilan gagal.
    ///
    /// # Errors
    ///
    /// Mengembalikan error jika:
    /// - Blob tidak ditemukan (`DAError::BlobNotFound`)
    /// - DA layer tidak tersedia (`DAError::Unavailable`)
    /// - Timeout saat mengambil data (`DAError::Timeout`)
    /// - Error jaringan (`DAError::NetworkError`)
    ///
    /// # Async Behavior
    ///
    /// Method ini async dan non-blocking. Future akan resolve
    /// setelah data berhasil diambil atau error terjadi.
    ///
    /// # Catatan
    ///
    /// Method ini TIDAK melakukan verifikasi integritas data.
    /// Verifikasi commitment adalah tanggung jawab implementor.
    fn get_blob(&self, blob_ref: &BlobRef) -> impl std::future::Future<Output = Result<Vec<u8>, DAError>> + Send;

    /// Subscribe ke stream blob pada namespace tertentu.
    ///
    /// Method ini mengembalikan stream yang akan menerima blob
    /// baru yang di-post ke namespace yang ditentukan secara real-time.
    ///
    /// # Arguments
    ///
    /// * `namespace` - Namespace 29-byte untuk di-subscribe.
    ///   Harus merupakan namespace yang valid di DA layer.
    ///
    /// # Returns
    ///
    /// `BlobStream` - Stream asinkron yang menghasilkan `Result<Blob, DAError>`.
    /// Stream akan terus aktif dan menghasilkan blob baru hingga di-drop.
    ///
    /// # Synchronous
    ///
    /// Method ini TIDAK async. Pembuatan stream dilakukan secara
    /// synchronous, namun konsumsi stream dilakukan secara async.
    ///
    /// # Stream Behavior
    ///
    /// - Stream bersifat `Send` dan dapat dikonsumsi dari thread manapun
    /// - Error pada stream dikembalikan sebagai `Result::Err` dalam item
    /// - Stream tidak akan terminate secara normal; hanya berhenti jika di-drop
    /// - Backpressure ditangani oleh implementor
    ///
    /// # Catatan
    ///
    /// Method ini TIDAK memfilter blob berdasarkan kriteria apapun
    /// selain namespace. Filtering tambahan adalah tanggung jawab caller.
    fn subscribe_blobs(&self, namespace: &[u8; 29]) -> BlobStream;

    /// Memeriksa status kesehatan DA layer.
    ///
    /// Method ini digunakan untuk monitoring dan health checking
    /// koneksi ke DA layer. Dapat dipanggil secara periodik untuk
    /// memantau status sistem.
    ///
    /// # Returns
    ///
    /// `DAHealthStatus` yang menunjukkan kondisi DA layer saat ini:
    /// - `Healthy` - DA layer beroperasi normal
    /// - `Degraded` - DA layer mengalami penurunan performa
    /// - `Unavailable` - DA layer tidak dapat dijangkau
    ///
    /// # Async Behavior
    ///
    /// Method ini async karena mungkin perlu melakukan request
    /// ke DA layer untuk verifikasi konektivitas dan status.
    ///
    /// # Catatan
    ///
    /// Method ini TIDAK memodifikasi state apapun dan aman
    /// untuk dipanggil berulang kali. Hasil mencerminkan kondisi
    /// pada saat pemanggilan dan dapat berubah sewaktu-waktu.
    fn health_check(&self) -> impl std::future::Future<Output = DAHealthStatus> + Send;

    /// Mengembalikan namespace yang digunakan oleh instance ini.
    ///
    /// Namespace adalah identifier 29-byte yang mengelompokkan
    /// blob dalam DA layer. Setiap instance `DALayer` terikat
    /// pada satu namespace.
    ///
    /// # Returns
    ///
    /// Referensi ke namespace 29-byte yang digunakan oleh instance ini.
    ///
    /// # Synchronous
    ///
    /// Method ini synchronous dan murah untuk dipanggil karena
    /// hanya mengembalikan referensi ke data yang sudah ada.
    ///
    /// # Catatan
    ///
    /// Namespace tidak berubah selama lifetime instance.
    /// Method ini TIDAK melakukan alokasi atau I/O.
    fn namespace(&self) -> &[u8; 29];
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ════════════════════════════════════════════════════════════════════════
    // BLOB TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_blob_creation() {
        let blob_ref = BlobRef {
            height: 12345,
            commitment: [0xAB; 32],
            namespace: [0xCD; 29],
        };

        let data = vec![1, 2, 3, 4, 5];
        let received_at = 1700000000000u64;

        let blob = Blob {
            ref_: blob_ref.clone(),
            data: data.clone(),
            received_at,
        };

        // Verify all fields stored correctly
        assert_eq!(blob.ref_.height, 12345);
        assert_eq!(blob.ref_.commitment, [0xAB; 32]);
        assert_eq!(blob.ref_.namespace, [0xCD; 29]);
        assert_eq!(blob.data, data);
        assert_eq!(blob.received_at, received_at);
    }

    #[test]
    fn test_blob_no_data_transformation() {
        let original_data = vec![0x00, 0xFF, 0x7F, 0x80, 0x01];
        
        let blob = Blob {
            ref_: BlobRef {
                height: 1,
                commitment: [0; 32],
                namespace: [0; 29],
            },
            data: original_data.clone(),
            received_at: 0,
        };

        // Data harus identik, tanpa transformasi
        assert_eq!(blob.data, original_data);
        assert_eq!(blob.data.len(), 5);
    }

    #[test]
    fn test_blob_empty_data() {
        let blob = Blob {
            ref_: BlobRef {
                height: 0,
                commitment: [0; 32],
                namespace: [0; 29],
            },
            data: vec![],
            received_at: 0,
        };

        assert!(blob.data.is_empty());
    }

    #[test]
    fn test_blob_large_data() {
        let large_data = vec![0xFFu8; 1_000_000]; // 1MB

        let blob = Blob {
            ref_: BlobRef {
                height: 999999,
                commitment: [0x11; 32],
                namespace: [0x22; 29],
            },
            data: large_data.clone(),
            received_at: u64::MAX,
        };

        assert_eq!(blob.data.len(), 1_000_000);
        assert_eq!(blob.data, large_data);
    }

    // ════════════════════════════════════════════════════════════════════════
    // DACONFIG DEFAULT TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_daconfig_default_all_fields_set() {
        let config = DAConfig::default();

        // All fields must be set
        assert!(!config.rpc_url.is_empty());
        assert_eq!(config.namespace.len(), 29);
        assert!(config.auth_token.is_none());
        assert!(config.timeout_ms > 0);
        assert!(config.retry_count > 0);
        assert!(config.retry_delay_ms > 0);
    }

    #[test]
    fn test_daconfig_default_values() {
        let config = DAConfig::default();

        assert_eq!(config.rpc_url, "http://localhost:26658");
        assert_eq!(config.namespace, [0u8; 29]);
        assert_eq!(config.auth_token, None);
        assert_eq!(config.timeout_ms, 30000);
        assert_eq!(config.retry_count, 3);
        assert_eq!(config.retry_delay_ms, 1000);
    }

    #[test]
    fn test_daconfig_default_consistent() {
        let config1 = DAConfig::default();
        let config2 = DAConfig::default();

        // Must be consistent across runs
        assert_eq!(config1, config2);
    }

    #[test]
    fn test_daconfig_default_namespace_size() {
        let config = DAConfig::default();
        
        // Namespace MUST be exactly 29 bytes
        assert_eq!(config.namespace.len(), 29);
    }

    // ════════════════════════════════════════════════════════════════════════
    // DACONFIG FROM_ENV TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_daconfig_from_env_missing_rpc_url() {
        // Clear any existing env vars
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");

        let result = DAConfig::from_env();
        assert!(result.is_err());
        
        let err = result.unwrap_err();
        assert!(matches!(err, DAError::Other(_)));
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
        std::env::set_var("DA_NAMESPACE", "0011223344"); // Too short (10 chars, need 58)

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
    fn test_daconfig_from_env_invalid_namespace_hex() {
        std::env::set_var("DA_RPC_URL", "http://test:1234");
        // 58 chars but invalid hex (contains 'GG')
        std::env::set_var("DA_NAMESPACE", "00112233445566778899AABBCCDDEEFF00112233445566778899AABBGG");

        let result = DAConfig::from_env();
        assert!(result.is_err());

        // Cleanup
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");
    }

    #[test]
    fn test_daconfig_from_env_invalid_timeout() {
        std::env::set_var("DA_RPC_URL", "http://test:1234");
        std::env::set_var("DA_NAMESPACE", "00112233445566778899aabbccddeeff00112233445566778899aabbcc");
        std::env::set_var("DA_TIMEOUT_MS", "not_a_number");

        let result = DAConfig::from_env();
        assert!(result.is_err());

        let err = result.unwrap_err();
        if let DAError::Other(msg) = err {
            assert!(msg.contains("DA_TIMEOUT_MS invalid"));
        } else {
            panic!("Expected DAError::Other");
        }

        // Cleanup
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");
        std::env::remove_var("DA_TIMEOUT_MS");
    }

    #[test]
    fn test_daconfig_from_env_invalid_retry_count() {
        std::env::set_var("DA_RPC_URL", "http://test:1234");
        std::env::set_var("DA_NAMESPACE", "00112233445566778899aabbccddeeff00112233445566778899aabbcc");
        std::env::set_var("DA_RETRY_COUNT", "256"); // Overflow for u8

        let result = DAConfig::from_env();
        assert!(result.is_err());

        // Cleanup
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");
        std::env::remove_var("DA_RETRY_COUNT");
    }

    #[test]
    fn test_daconfig_from_env_invalid_retry_delay() {
        std::env::set_var("DA_RPC_URL", "http://test:1234");
        std::env::set_var("DA_NAMESPACE", "00112233445566778899aabbccddeeff00112233445566778899aabbcc");
        std::env::set_var("DA_RETRY_DELAY_MS", "-1"); // Negative

        let result = DAConfig::from_env();
        assert!(result.is_err());

        // Cleanup
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");
        std::env::remove_var("DA_RETRY_DELAY_MS");
    }

    #[test]
    fn test_daconfig_from_env_success_minimal() {
        // Set required env vars
        std::env::set_var("DA_RPC_URL", "http://celestia:26658");
        std::env::set_var("DA_NAMESPACE", "00112233445566778899aabbccddeeff00112233445566778899aabbcc");

        let result = DAConfig::from_env();
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.rpc_url, "http://celestia:26658");
        assert_eq!(config.auth_token, None);
        // Defaults should be used
        assert_eq!(config.timeout_ms, 30000);
        assert_eq!(config.retry_count, 3);
        assert_eq!(config.retry_delay_ms, 1000);

        // Cleanup
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");
    }

    #[test]
    fn test_daconfig_from_env_success_full() {
        std::env::set_var("DA_RPC_URL", "http://celestia:26658");
        std::env::set_var("DA_NAMESPACE", "00112233445566778899aabbccddeeff00112233445566778899aabbcc");
        std::env::set_var("DA_AUTH_TOKEN", "secret_token_123");
        std::env::set_var("DA_TIMEOUT_MS", "60000");
        std::env::set_var("DA_RETRY_COUNT", "5");
        std::env::set_var("DA_RETRY_DELAY_MS", "2000");

        let result = DAConfig::from_env();
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.rpc_url, "http://celestia:26658");
        assert_eq!(config.auth_token, Some("secret_token_123".to_string()));
        assert_eq!(config.timeout_ms, 60000);
        assert_eq!(config.retry_count, 5);
        assert_eq!(config.retry_delay_ms, 2000);

        // Verify namespace parsed correctly
        let expected_namespace: [u8; 29] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC,
        ];
        assert_eq!(config.namespace, expected_namespace);

        // Cleanup
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");
        std::env::remove_var("DA_AUTH_TOKEN");
        std::env::remove_var("DA_TIMEOUT_MS");
        std::env::remove_var("DA_RETRY_COUNT");
        std::env::remove_var("DA_RETRY_DELAY_MS");
    }

    #[test]
    fn test_daconfig_from_env_auth_token_optional() {
        std::env::set_var("DA_RPC_URL", "http://test:1234");
        std::env::set_var("DA_NAMESPACE", "00112233445566778899aabbccddeeff00112233445566778899aabbcc");
        std::env::remove_var("DA_AUTH_TOKEN");

        let result = DAConfig::from_env();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().auth_token, None);

        // Cleanup
        std::env::remove_var("DA_RPC_URL");
        std::env::remove_var("DA_NAMESPACE");
    }

    // ════════════════════════════════════════════════════════════════════════
    // BLOB REF TESTS (sanity check - not modified)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_blob_ref_equality() {
        let ref1 = BlobRef {
            height: 100,
            commitment: [0x11; 32],
            namespace: [0x22; 29],
        };

        let ref2 = BlobRef {
            height: 100,
            commitment: [0x11; 32],
            namespace: [0x22; 29],
        };

        assert_eq!(ref1, ref2);
    }

    #[test]
    fn test_blob_ref_clone() {
        let original = BlobRef {
            height: 999,
            commitment: [0xFF; 32],
            namespace: [0xAA; 29],
        };

        let cloned = original.clone();
        assert_eq!(original, cloned);
    }
}