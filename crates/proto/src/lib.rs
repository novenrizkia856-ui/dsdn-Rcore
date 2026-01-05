//! # DSDN Proto Crate
//!
//! Proto crate adalah definisi schema resmi untuk Data Availability (DA) events
//! dalam sistem DSDN (Distributed Storage and Data Network).
//!
//! ## Module Overview
//!
//! Crate ini menyediakan:
//! - Definisi event types untuk komunikasi dengan Celestia DA layer
//! - Deterministic serialization untuk konsensus dan verifikasi
//! - Health status dan error types untuk monitoring DA layer
//! - Encoding helpers untuk serialization dan hashing
//!
//! Proto crate adalah kontrak data antara komponen DSDN:
//! - **Coordinator**: Membuat dan mengirim events ke DA layer
//! - **Storage Nodes**: Menerima dan memproses events dari DA layer
//! - **Validators**: Memverifikasi events dan state transitions
//!
//! ## Modules
//!
//! - [`da_event`]: DAEvent enum dan semua event struct types
//! - [`da_health`]: DAHealthStatus dan DAError types
//! - [`encoding`]: Serialization helpers untuk deterministic encoding
//!
//! ## Event Lifecycle
//!
//! ```text
//! ┌─────────────────┐
//! │  Create Event   │  Buat DAEvent dengan semua field
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │  encode_event   │  Serialize ke deterministic bytes (bincode)
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │compute_event_hash│  SHA3-256 hash dari encoded bytes
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │  Post to DA     │  Kirim ke Celestia DA layer
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │  decode_event   │  Deserialize dari bytes
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │ Verify & Process│  Validasi hash dan proses event
//! └─────────────────┘
//! ```
//!
//! ## Serialization Format Specification
//!
//! ### Deterministic Encoding
//!
//! Semua events di-encode menggunakan bincode dengan konfigurasi:
//! - Little-endian byte order
//! - Fixed integer encoding (tidak variable-length)
//! - String di-encode dengan length prefix (u64)
//! - Enum variants di-encode sebagai u32 discriminant + payload
//!
//! ### Field Order
//!
//! Field di-serialize sesuai urutan definisi di struct.
//! Urutan field TIDAK BOLEH diubah untuk menjaga backward compatibility.
//!
//! ### Batch Encoding Format
//!
//! ```text
//! [event_count: u64 LE][event_1_len: u64 LE][event_1_bytes]...[event_N_len: u64 LE][event_N_bytes]
//! ```
//!
//! - `event_count`: Jumlah events dalam batch (8 bytes, little-endian)
//! - `event_N_len`: Panjang bytes event ke-N (8 bytes, little-endian)
//! - `event_N_bytes`: Encoded bytes event ke-N
//!
//! ### Hash Computation
//!
//! Event hash dihitung dengan:
//! 1. Encode event ke bytes menggunakan `encode_event`
//! 2. Compute SHA3-256 hash dari encoded bytes
//! 3. Output: fixed 32 bytes
//!
//! ## Version Compatibility
//!
//! ### Current Version
//!
//! Proto version: 0.1
//!
//! ### Backward Compatibility Rules
//!
//! Yang TIDAK BOLEH berubah:
//! - Nama dan urutan field dalam struct
//! - Encoding format (bincode little-endian)
//! - Hash algorithm (SHA3-256)
//! - Batch encoding format
//!
//! Yang BOLEH ditambahkan:
//! - Variant baru di DAEvent enum (di akhir)
//! - Field baru di struct event (dengan default value)
//!
//! ### Forward Compatibility
//!
//! Decoder versi lama akan gagal decode event dari versi baru
//! jika ada variant atau field yang tidak dikenal.
//! Gunakan version field di DAEvent untuk deteksi.
//!
//! ## Event Types
//!
//! | Event | Deskripsi |
//! |-------|-----------|
//! | `NodeRegistered` | Node baru bergabung ke network |
//! | `ChunkDeclared` | Chunk baru dideklarasikan |
//! | `ReplicaAdded` | Replica ditambahkan ke node |
//! | `ReplicaRemoved` | Replica dihapus dari node |
//! | `DeleteRequested` | Request penghapusan chunk |

pub mod da_event;
pub mod da_health;
pub mod encoding;

pub use da_health::{DAHealthStatus, DAError};
pub use encoding::*;

/// Proto crate version string
pub const PROTO_VERSION: &str = "0.1";