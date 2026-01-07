//! Data Availability Layer Abstraction
//!
//! Modul ini mendefinisikan trait `DALayer` sebagai kontrak abstraksi
//! untuk Data Availability layer dalam sistem DSDN. Trait ini memungkinkan
//! DSDN berinteraksi dengan berbagai backend DA secara seragam tanpa
//! terikat pada implementasi spesifik.

use std::future::Future;
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
    /// Blob dengan referensi yang diberikan tidak ditemukan.
    /// Menyimpan `BlobRef` yang dicari untuk keperluan diagnostik.
    BlobNotFound(BlobRef),
    
    /// Blob ditemukan tetapi data tidak valid.
    /// Terjadi ketika commitment tidak cocok dengan data yang diterima,
    /// mengindikasikan data korupsi atau blob yang salah.
    InvalidBlob,
    
    /// Namespace yang diberikan tidak valid atau tidak cocok.
    /// Terjadi ketika namespace pada request tidak cocok dengan
    /// namespace aktif pada CelestiaDA instance.
    InvalidNamespace,
    
    /// Timeout saat berkomunikasi dengan DA layer.
    /// Operasi melebihi batas waktu yang dikonfigurasi.
    Timeout,
    
    /// DA layer tidak tersedia atau tidak dapat dijangkau.
    /// Berbeda dengan NetworkError, ini mengindikasikan bahwa
    /// DA layer secara eksplisit tidak dapat diakses.
    Unavailable,
    
    /// Error jaringan saat berkomunikasi dengan DA layer.
    /// Menyimpan pesan detail tentang error yang terjadi.
    NetworkError(String),
    
    /// Error serialisasi atau deserialisasi data.
    /// Terjadi saat encoding/decoding JSON-RPC atau base64.
    SerializationError(String),
    
    /// Error lainnya yang tidak terkategorikan.
    /// Digunakan untuk error yang tidak masuk kategori di atas.
    Other(String),
}

impl std::fmt::Display for DAError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DAError::BlobNotFound(ref_) => write!(
                f, 
                "blob not found at height {} with commitment {:?}", 
                ref_.height,
                &ref_.commitment[..8] // Show first 8 bytes for brevity
            ),
            DAError::InvalidBlob => write!(f, "blob data invalid: commitment mismatch"),
            DAError::InvalidNamespace => write!(f, "namespace mismatch"),
            DAError::Timeout => write!(f, "operation timed out"),
            DAError::Unavailable => write!(f, "DA layer unavailable"),
            DAError::NetworkError(msg) => write!(f, "network error: {}", msg),
            DAError::SerializationError(msg) => write!(f, "serialization error: {}", msg),
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
    fn post_blob<'a>(&'a self, data: &'a [u8]) -> Pin<Box<dyn Future<Output = Result<BlobRef, DAError>> + Send + 'a>>;

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
    /// * `Ok(Vec<u8>)` - Data blob mentah yang berhasil diambil.
    /// * `Err(DAError)` - Error jika pengambilan gagal.
    ///
    /// # Errors
    ///
    /// Mengembalikan error jika:
    /// - Blob tidak ditemukan (`DAError::BlobNotFound`)
    /// - Blob data tidak valid / commitment mismatch (`DAError::InvalidBlob`)
    /// - Namespace tidak cocok (`DAError::InvalidNamespace`)
    /// - Timeout saat mengambil (`DAError::Timeout`)
    /// - Error jaringan (`DAError::NetworkError`)
    ///
    /// # Async Behavior
    ///
    /// Method ini async dan non-blocking. Future akan resolve setelah
    /// data berhasil diambil dan divalidasi dari DA layer.
    ///
    /// # Validasi
    ///
    /// Implementasi WAJIB melakukan validasi:
    /// - Namespace pada response cocok dengan namespace aktif
    /// - Commitment dari data cocok dengan `blob_ref.commitment`
    /// 
    /// Jika validasi gagal, kembalikan error yang sesuai tanpa
    /// mengembalikan data yang tidak valid.
    fn get_blob<'a>(&'a self, blob_ref: &'a BlobRef) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DAError>> + Send + 'a>>;

    /// Subscribe ke stream blob baru di DA layer.
    ///
    /// Method ini memulai subscription ke DA layer untuk menerima
    /// notifikasi setiap kali ada blob baru yang masuk ke namespace
    /// yang dikonfigurasi.
    ///
    /// # Arguments
    ///
    /// * `from_height` - Height awal untuk mulai subscribe.
    ///   Jika `None`, subscribe dari height terbaru.
    ///   Jika `Some(height)`, subscribe mulai dari height tersebut.
    ///
    /// # Returns
    ///
    /// * `Ok(BlobStream)` - Stream asinkron yang yield `Blob` baru.
    /// * `Err(DAError)` - Error jika subscription gagal dimulai.
    ///
    /// # Stream Behavior
    ///
    /// - Stream akan terus aktif sampai di-drop atau terjadi error fatal
    /// - Jika koneksi terputus, implementasi HARUS melakukan reconnect
    /// - Error transient dikirim melalui stream, bukan terminate stream
    /// - Stream TIDAK BOLEH miss blob (at-least-once delivery)
    ///
    /// # Ordering
    ///
    /// Blob dijamin terurut berdasarkan height. Blob dengan height
    /// lebih rendah akan di-yield sebelum blob dengan height lebih tinggi.
    fn subscribe_blobs(&self, from_height: Option<u64>) -> Pin<Box<dyn Future<Output = Result<BlobStream, DAError>> + Send + '_>>;

    /// Memeriksa kesehatan koneksi ke DA layer.
    ///
    /// Method ini melakukan health check ke DA layer untuk memverifikasi
    /// bahwa koneksi aktif dan DA layer dapat menerima request.
    ///
    /// # Returns
    ///
    /// * `Ok(DAHealthStatus)` - Status kesehatan DA layer.
    /// * `Err(DAError)` - Error jika health check gagal dilakukan.
    ///
    /// # Health Status
    ///
    /// - `Healthy`: DA layer beroperasi normal
    /// - `Degraded`: DA layer beroperasi tapi ada masalah performa
    /// - `Unavailable`: DA layer tidak dapat diakses
    ///
    /// # Async Behavior
    ///
    /// Method ini async dan HARUS:
    /// - Memiliki timeout internal yang reasonable
    /// - Tidak block lebih dari beberapa detik
    /// - Menggunakan request ringan (minimal overhead)
    fn health_check(&self) -> Pin<Box<dyn Future<Output = Result<DAHealthStatus, DAError>> + Send + '_>>;
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ════════════════════════════════════════════════════════════════════════
    // BLOB REF TESTS
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
    fn test_blob_ref_inequality_height() {
        let ref1 = BlobRef {
            height: 100,
            commitment: [0x11; 32],
            namespace: [0x22; 29],
        };

        let ref2 = BlobRef {
            height: 101, // Different
            commitment: [0x11; 32],
            namespace: [0x22; 29],
        };

        assert_ne!(ref1, ref2);
    }

    #[test]
    fn test_blob_ref_inequality_commitment() {
        let ref1 = BlobRef {
            height: 100,
            commitment: [0x11; 32],
            namespace: [0x22; 29],
        };

        let ref2 = BlobRef {
            height: 100,
            commitment: [0x12; 32], // Different
            namespace: [0x22; 29],
        };

        assert_ne!(ref1, ref2);
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

    #[test]
    fn test_blob_ref_hash() {
        use std::collections::HashMap;
        
        let ref1 = BlobRef {
            height: 100,
            commitment: [0x11; 32],
            namespace: [0x22; 29],
        };

        let mut map: HashMap<BlobRef, String> = HashMap::new();
        map.insert(ref1.clone(), "test".to_string());
        
        assert_eq!(map.get(&ref1), Some(&"test".to_string()));
    }

    // ════════════════════════════════════════════════════════════════════════
    // DA ERROR TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_daerror_blob_not_found_display() {
        let blob_ref = BlobRef {
            height: 12345,
            commitment: [0xAB; 32],
            namespace: [0x01; 29],
        };
        
        let error = DAError::BlobNotFound(blob_ref);
        let display = format!("{}", error);
        
        assert!(display.contains("blob not found"));
        assert!(display.contains("12345"));
    }

    #[test]
    fn test_daerror_blob_not_found_contains_ref() {
        let blob_ref = BlobRef {
            height: 999,
            commitment: [0xCD; 32],
            namespace: [0x02; 29],
        };
        
        let error = DAError::BlobNotFound(blob_ref.clone());
        
        if let DAError::BlobNotFound(ref_) = error {
            assert_eq!(ref_.height, 999);
            assert_eq!(ref_.commitment, [0xCD; 32]);
        } else {
            panic!("Expected BlobNotFound variant");
        }
    }

    #[test]
    fn test_daerror_invalid_blob_display() {
        let error = DAError::InvalidBlob;
        let display = format!("{}", error);
        
        assert!(display.contains("invalid") || display.contains("mismatch"));
    }

    #[test]
    fn test_daerror_invalid_namespace_display() {
        let error = DAError::InvalidNamespace;
        let display = format!("{}", error);
        
        assert!(display.contains("namespace"));
    }

    #[test]
    fn test_daerror_timeout_display() {
        let error = DAError::Timeout;
        let display = format!("{}", error);
        
        assert!(display.contains("timeout") || display.contains("timed out"));
    }

    #[test]
    fn test_daerror_unavailable_display() {
        let error = DAError::Unavailable;
        let display = format!("{}", error);
        
        assert!(display.contains("unavailable"));
    }

    #[test]
    fn test_daerror_network_error_display() {
        let error = DAError::NetworkError("connection refused".to_string());
        let display = format!("{}", error);
        
        assert!(display.contains("network"));
        assert!(display.contains("connection refused"));
    }

    #[test]
    fn test_daerror_serialization_error_display() {
        let error = DAError::SerializationError("invalid JSON".to_string());
        let display = format!("{}", error);
        
        assert!(display.contains("serialization"));
        assert!(display.contains("invalid JSON"));
    }

    #[test]
    fn test_daerror_other_display() {
        let error = DAError::Other("custom error message".to_string());
        let display = format!("{}", error);
        
        assert!(display.contains("custom error message"));
    }

    #[test]
    fn test_daerror_equality() {
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
        
        assert_eq!(
            DAError::BlobNotFound(ref1.clone()),
            DAError::BlobNotFound(ref2.clone())
        );
        assert_eq!(DAError::InvalidBlob, DAError::InvalidBlob);
        assert_eq!(DAError::InvalidNamespace, DAError::InvalidNamespace);
        assert_eq!(DAError::Timeout, DAError::Timeout);
        assert_eq!(DAError::Unavailable, DAError::Unavailable);
        assert_eq!(
            DAError::NetworkError("test".to_string()),
            DAError::NetworkError("test".to_string())
        );
    }

    #[test]
    fn test_daerror_inequality() {
        let ref1 = BlobRef {
            height: 100,
            commitment: [0x11; 32],
            namespace: [0x22; 29],
        };
        
        let ref2 = BlobRef {
            height: 200, // Different
            commitment: [0x11; 32],
            namespace: [0x22; 29],
        };
        
        assert_ne!(
            DAError::BlobNotFound(ref1),
            DAError::BlobNotFound(ref2)
        );
        assert_ne!(DAError::InvalidBlob, DAError::InvalidNamespace);
        assert_ne!(DAError::Timeout, DAError::Unavailable);
    }

    #[test]
    fn test_daerror_clone() {
        let blob_ref = BlobRef {
            height: 500,
            commitment: [0xEE; 32],
            namespace: [0xFF; 29],
        };
        
        let error = DAError::BlobNotFound(blob_ref);
        let cloned = error.clone();
        
        assert_eq!(error, cloned);
    }

    // ════════════════════════════════════════════════════════════════════════
    // DA HEALTH STATUS TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_dahealthstatus_equality() {
        assert_eq!(DAHealthStatus::Healthy, DAHealthStatus::Healthy);
        assert_eq!(DAHealthStatus::Degraded, DAHealthStatus::Degraded);
        assert_eq!(DAHealthStatus::Unavailable, DAHealthStatus::Unavailable);
    }

    #[test]
    fn test_dahealthstatus_inequality() {
        assert_ne!(DAHealthStatus::Healthy, DAHealthStatus::Degraded);
        assert_ne!(DAHealthStatus::Healthy, DAHealthStatus::Unavailable);
        assert_ne!(DAHealthStatus::Degraded, DAHealthStatus::Unavailable);
    }

    #[test]
    fn test_dahealthstatus_copy() {
        let status = DAHealthStatus::Healthy;
        let copied = status; // Copy, not move
        assert_eq!(status, copied);
    }

    // ════════════════════════════════════════════════════════════════════════
    // DA CONFIG TESTS
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_daconfig_default() {
        let config = DAConfig::default();
        
        assert_eq!(config.rpc_url, "http://localhost:26658");
        assert_eq!(config.namespace, [0u8; 29]);
        assert_eq!(config.auth_token, None);
        assert_eq!(config.timeout_ms, 30000);
        assert_eq!(config.retry_count, 3);
        assert_eq!(config.retry_delay_ms, 1000);
    }

    #[test]
    fn test_daconfig_clone() {
        let config = DAConfig {
            rpc_url: "http://test:1234".to_string(),
            namespace: [0x11; 29],
            auth_token: Some("token".to_string()),
            timeout_ms: 5000,
            retry_count: 5,
            retry_delay_ms: 500,
        };
        
        let cloned = config.clone();
        assert_eq!(config, cloned);
    }

    #[test]
    fn test_daconfig_equality() {
        let config1 = DAConfig::default();
        let config2 = DAConfig::default();
        assert_eq!(config1, config2);
    }

    #[test]
    fn test_daconfig_inequality() {
        let config1 = DAConfig::default();
        let mut config2 = DAConfig::default();
        config2.timeout_ms = 9999;
        
        assert_ne!(config1, config2);
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

    #[test]
    fn test_blob_clone() {
        let blob = Blob {
            ref_: BlobRef {
                height: 200,
                commitment: [0xAA; 32],
                namespace: [0xBB; 29],
            },
            data: vec![10, 20, 30],
            received_at: 9999,
        };

        let cloned = blob.clone();
        
        assert_eq!(blob.ref_, cloned.ref_);
        assert_eq!(blob.data, cloned.data);
        assert_eq!(blob.received_at, cloned.received_at);
    }

    #[test]
    fn test_blob_empty_data() {
        let blob = Blob {
            ref_: BlobRef {
                height: 1,
                commitment: [0x00; 32],
                namespace: [0x00; 29],
            },
            data: vec![],
            received_at: 0,
        };

        assert!(blob.data.is_empty());
    }
}