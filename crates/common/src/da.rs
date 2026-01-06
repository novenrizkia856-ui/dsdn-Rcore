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
/// dari DA layer, beserta referensi untuk identifikasi.
#[derive(Debug, Clone)]
pub struct Blob {
    /// Data mentah blob
    pub data: Vec<u8>,
    /// Referensi ke blob ini di DA layer
    pub blob_ref: BlobRef,
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