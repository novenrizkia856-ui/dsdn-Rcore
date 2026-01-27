//! # Coordinator Identifier Types
//!
//! Module ini menyediakan identifier types untuk sistem multi-coordinator DSDN.
//!
//! ## Types
//!
//! | Type | Deskripsi | Ukuran |
//! |------|-----------|--------|
//! | `CoordinatorId` | Identifier unik untuk coordinator node | 32 bytes |
//! | `ValidatorId` | Identifier unik untuk validator node | 32 bytes |
//! | `WorkloadId` | Identifier unik untuk workload/task | 32 bytes |
//! | `Timestamp` | Unix timestamp dalam detik | u64 |
//!
//! ## Karakteristik
//!
//! Semua identifier types memiliki:
//! - Representasi internal `[u8; 32]`
//! - Derivasi: Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize
//! - Konversi hex (lowercase, deterministik)
//! - Aman untuk HashMap/HashSet
//!
//! ## Keamanan
//!
//! - Tidak ada panic dalam konversi
//! - Error handling eksplisit via `ParseError`
//! - Deterministik untuk semua operasi

use serde::{Deserialize, Serialize};
use std::fmt;

// ════════════════════════════════════════════════════════════════════════════════
// ERROR TYPE
// ════════════════════════════════════════════════════════════════════════════════

/// Error type untuk parsing identifier dari hex string.
///
/// Digunakan oleh `from_hex` methods pada semua identifier types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Hex string memiliki panjang yang tidak valid.
    /// Expected: 64 karakter untuk 32 bytes.
    InvalidLength {
        /// Panjang yang diterima.
        got: usize,
        /// Panjang yang diharapkan.
        expected: usize,
    },

    /// Hex string mengandung karakter non-hex.
    InvalidHexCharacter {
        /// Karakter yang tidak valid.
        character: char,
        /// Posisi karakter dalam string.
        position: usize,
    },

    /// Error umum saat decode hex.
    DecodeError(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidLength { got, expected } => {
                write!(
                    f,
                    "invalid hex length: got {} characters, expected {}",
                    got, expected
                )
            }
            ParseError::InvalidHexCharacter {
                character,
                position,
            } => {
                write!(
                    f,
                    "invalid hex character '{}' at position {}",
                    character, position
                )
            }
            ParseError::DecodeError(msg) => {
                write!(f, "hex decode error: {}", msg)
            }
        }
    }
}

impl std::error::Error for ParseError {}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Encode bytes ke lowercase hex string.
///
/// Deterministik dan selalu menghasilkan lowercase output.
#[inline]
fn bytes_to_hex(bytes: &[u8; 32]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in bytes {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

/// Decode hex string ke bytes.
///
/// Validasi:
/// - Panjang harus 64 karakter
/// - Semua karakter harus valid hex (0-9, a-f, A-F)
fn hex_to_bytes(hex: &str) -> Result<[u8; 32], ParseError> {
    // Validate length
    if hex.len() != 64 {
        return Err(ParseError::InvalidLength {
            got: hex.len(),
            expected: 64,
        });
    }

    // Validate characters and decode
    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let high = hex_char_to_nibble(chunk[0] as char, i * 2)?;
        let low = hex_char_to_nibble(chunk[1] as char, i * 2 + 1)?;
        bytes[i] = (high << 4) | low;
    }

    Ok(bytes)
}

/// Convert single hex character to nibble (4 bits).
#[inline]
fn hex_char_to_nibble(c: char, position: usize) -> Result<u8, ParseError> {
    match c {
        '0'..='9' => Ok(c as u8 - b'0'),
        'a'..='f' => Ok(c as u8 - b'a' + 10),
        'A'..='F' => Ok(c as u8 - b'A' + 10),
        _ => Err(ParseError::InvalidHexCharacter {
            character: c,
            position,
        }),
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// COORDINATOR ID
// ════════════════════════════════════════════════════════════════════════════════

/// Identifier unik untuk coordinator node dalam sistem multi-coordinator.
///
/// `CoordinatorId` adalah identifier 32-byte yang digunakan untuk
/// mengidentifikasi coordinator nodes secara unik dalam jaringan DSDN.
///
/// ## Karakteristik
///
/// - Immutable setelah construction
/// - Copy-able (32 bytes cukup kecil)
/// - Aman untuk HashMap key (implements Hash + Eq)
/// - Serialize/Deserialize stabil
///
/// ## Contoh
///
/// ```rust,ignore
/// use dsdn_common::CoordinatorId;
///
/// // Dari bytes
/// let id = CoordinatorId::new([0x42; 32]);
///
/// // Ke hex
/// let hex = id.to_hex();
///
/// // Dari hex
/// let id2 = CoordinatorId::from_hex(&hex)?;
/// assert_eq!(id, id2);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CoordinatorId([u8; 32]);

impl CoordinatorId {
    /// Membuat `CoordinatorId` dari bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - 32-byte array sebagai identifier
    ///
    /// # Returns
    ///
    /// `CoordinatorId` baru dengan bytes yang diberikan.
    #[must_use]
    #[inline]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Membuat `CoordinatorId` dari slice bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Slice bytes untuk konversi
    ///
    /// # Returns
    ///
    /// - `Some(CoordinatorId)` jika panjang slice = 32
    /// - `None` jika panjang tidak sesuai
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Some(Self(arr))
    }

    /// Mengembalikan reference ke inner bytes.
    ///
    /// # Returns
    ///
    /// Reference ke 32-byte array internal.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Mengkonversi ke lowercase hex string.
    ///
    /// Output selalu 64 karakter lowercase hex.
    /// Deterministik untuk bytes yang sama.
    ///
    /// # Returns
    ///
    /// String hex lowercase (64 karakter).
    #[must_use]
    pub fn to_hex(&self) -> String {
        bytes_to_hex(&self.0)
    }

    /// Membuat `CoordinatorId` dari hex string.
    ///
    /// Menerima lowercase atau uppercase hex.
    /// Panjang harus tepat 64 karakter.
    ///
    /// # Arguments
    ///
    /// * `hex` - Hex string (64 karakter)
    ///
    /// # Errors
    ///
    /// - `ParseError::InvalidLength` jika panjang != 64
    /// - `ParseError::InvalidHexCharacter` jika ada karakter non-hex
    pub fn from_hex(hex: &str) -> Result<Self, ParseError> {
        let bytes = hex_to_bytes(hex)?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for CoordinatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display first 8 chars of hex for readability
        let hex = self.to_hex();
        write!(f, "CoordinatorId({}...)", &hex[..8])
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// VALIDATOR ID
// ════════════════════════════════════════════════════════════════════════════════

/// Identifier unik untuk validator node.
///
/// `ValidatorId` adalah identifier 32-byte yang digunakan untuk
/// mengidentifikasi validator nodes dalam sistem DSDN.
///
/// ## Karakteristik
///
/// Identik dengan `CoordinatorId`:
/// - Immutable setelah construction
/// - Copy-able (32 bytes)
/// - Aman untuk HashMap key
/// - Serialize/Deserialize stabil
///
/// ## Contoh
///
/// ```rust,ignore
/// use dsdn_common::ValidatorId;
///
/// let id = ValidatorId::new([0x42; 32]);
/// let hex = id.to_hex();
/// let id2 = ValidatorId::from_hex(&hex)?;
/// assert_eq!(id, id2);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValidatorId([u8; 32]);

impl ValidatorId {
    /// Membuat `ValidatorId` dari bytes.
    #[must_use]
    #[inline]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Membuat `ValidatorId` dari slice bytes.
    ///
    /// # Returns
    ///
    /// - `Some(ValidatorId)` jika panjang slice = 32
    /// - `None` jika panjang tidak sesuai
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Some(Self(arr))
    }

    /// Mengembalikan reference ke inner bytes.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Mengkonversi ke lowercase hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        bytes_to_hex(&self.0)
    }

    /// Membuat `ValidatorId` dari hex string.
    ///
    /// # Errors
    ///
    /// - `ParseError::InvalidLength` jika panjang != 64
    /// - `ParseError::InvalidHexCharacter` jika ada karakter non-hex
    pub fn from_hex(hex: &str) -> Result<Self, ParseError> {
        let bytes = hex_to_bytes(hex)?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for ValidatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.to_hex();
        write!(f, "ValidatorId({}...)", &hex[..8])
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// WORKLOAD ID
// ════════════════════════════════════════════════════════════════════════════════

/// Identifier unik untuk workload/task dalam sistem DSDN.
///
/// `WorkloadId` adalah identifier 32-byte yang digunakan untuk
/// mengidentifikasi workloads atau tasks secara unik.
///
/// ## Karakteristik
///
/// Identik dengan `CoordinatorId`:
/// - Immutable setelah construction
/// - Copy-able (32 bytes)
/// - Aman untuk HashMap key
/// - Serialize/Deserialize stabil
///
/// ## Contoh
///
/// ```rust,ignore
/// use dsdn_common::WorkloadId;
///
/// let id = WorkloadId::new([0x42; 32]);
/// let hex = id.to_hex();
/// let id2 = WorkloadId::from_hex(&hex)?;
/// assert_eq!(id, id2);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkloadId([u8; 32]);

impl WorkloadId {
    /// Membuat `WorkloadId` dari bytes.
    #[must_use]
    #[inline]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Membuat `WorkloadId` dari slice bytes.
    ///
    /// # Returns
    ///
    /// - `Some(WorkloadId)` jika panjang slice = 32
    /// - `None` jika panjang tidak sesuai
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Some(Self(arr))
    }

    /// Mengembalikan reference ke inner bytes.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Mengkonversi ke lowercase hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        bytes_to_hex(&self.0)
    }

    /// Membuat `WorkloadId` dari hex string.
    ///
    /// # Errors
    ///
    /// - `ParseError::InvalidLength` jika panjang != 64
    /// - `ParseError::InvalidHexCharacter` jika ada karakter non-hex
    pub fn from_hex(hex: &str) -> Result<Self, ParseError> {
        let bytes = hex_to_bytes(hex)?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for WorkloadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.to_hex();
        write!(f, "WorkloadId({}...)", &hex[..8])
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TIMESTAMP
// ════════════════════════════════════════════════════════════════════════════════

/// Unix timestamp dalam detik.
///
/// Type alias untuk `u64` yang merepresentasikan waktu sebagai
/// jumlah detik sejak Unix epoch (1970-01-01 00:00:00 UTC).
///
/// ## Catatan
///
/// - Tidak ada helper logic tambahan
/// - Gunakan library eksternal (chrono, time) untuk konversi
/// - Nilai 0 valid (Unix epoch)
pub type Timestamp = u64;

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    // ────────────────────────────────────────────────────────────────────────────
    // PARSE ERROR TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_error_invalid_length_display() {
        let err = ParseError::InvalidLength {
            got: 32,
            expected: 64,
        };
        let msg = err.to_string();
        assert!(msg.contains("32"));
        assert!(msg.contains("64"));
    }

    #[test]
    fn test_parse_error_invalid_hex_character_display() {
        let err = ParseError::InvalidHexCharacter {
            character: 'g',
            position: 5,
        };
        let msg = err.to_string();
        assert!(msg.contains("'g'"));
        assert!(msg.contains("5"));
    }

    #[test]
    fn test_parse_error_decode_error_display() {
        let err = ParseError::DecodeError("test error".to_string());
        let msg = err.to_string();
        assert!(msg.contains("test error"));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // COORDINATOR ID TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_coordinator_id_new() {
        let bytes = [0x42u8; 32];
        let id = CoordinatorId::new(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn test_coordinator_id_from_bytes_valid() {
        let bytes = [0x42u8; 32];
        let id = CoordinatorId::from_bytes(&bytes);
        assert!(id.is_some());
        assert_eq!(id.unwrap().as_bytes(), &bytes);
    }

    #[test]
    fn test_coordinator_id_from_bytes_invalid_length() {
        let bytes = [0x42u8; 16]; // Too short
        let id = CoordinatorId::from_bytes(&bytes);
        assert!(id.is_none());

        let bytes_long = [0x42u8; 64]; // Too long
        let id = CoordinatorId::from_bytes(&bytes_long);
        assert!(id.is_none());
    }

    #[test]
    fn test_coordinator_id_to_hex() {
        let bytes = [0x00u8; 32];
        let id = CoordinatorId::new(bytes);
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, "0".repeat(64));

        let bytes2 = [0xffu8; 32];
        let id2 = CoordinatorId::new(bytes2);
        let hex2 = id2.to_hex();
        assert_eq!(hex2.len(), 64);
        assert_eq!(hex2, "f".repeat(64)); // Lowercase
    }

    #[test]
    fn test_coordinator_id_from_hex_valid_lowercase() {
        let hex = "a".repeat(64);
        let id = CoordinatorId::from_hex(&hex);
        assert!(id.is_ok());
        assert_eq!(id.unwrap().as_bytes(), &[0xaa; 32]);
    }

    #[test]
    fn test_coordinator_id_from_hex_valid_uppercase() {
        let hex = "A".repeat(64);
        let id = CoordinatorId::from_hex(&hex);
        assert!(id.is_ok());
        assert_eq!(id.unwrap().as_bytes(), &[0xaa; 32]);
    }

    #[test]
    fn test_coordinator_id_from_hex_valid_mixed_case() {
        let hex = "aA".repeat(32);
        let id = CoordinatorId::from_hex(&hex);
        assert!(id.is_ok());
    }

    #[test]
    fn test_coordinator_id_from_hex_invalid_length() {
        let hex = "a".repeat(32); // Too short
        let result = CoordinatorId::from_hex(&hex);
        assert!(result.is_err());

        match result.unwrap_err() {
            ParseError::InvalidLength { got, expected } => {
                assert_eq!(got, 32);
                assert_eq!(expected, 64);
            }
            _ => panic!("Expected InvalidLength error"),
        }
    }

    #[test]
    fn test_coordinator_id_from_hex_invalid_character() {
        let mut hex = "0".repeat(63);
        hex.push('g'); // Invalid hex character
        let result = CoordinatorId::from_hex(&hex);
        assert!(result.is_err());

        match result.unwrap_err() {
            ParseError::InvalidHexCharacter { character, position } => {
                assert_eq!(character, 'g');
                assert_eq!(position, 63);
            }
            _ => panic!("Expected InvalidHexCharacter error"),
        }
    }

    #[test]
    fn test_coordinator_id_roundtrip() {
        let original = CoordinatorId::new([0x42; 32]);
        let hex = original.to_hex();
        let recovered = CoordinatorId::from_hex(&hex).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_coordinator_id_copy() {
        let id1 = CoordinatorId::new([0x42; 32]);
        let id2 = id1; // Copy
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_coordinator_id_hash_eq() {
        let id1 = CoordinatorId::new([0x42; 32]);
        let id2 = CoordinatorId::new([0x42; 32]);
        let id3 = CoordinatorId::new([0x43; 32]);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);

        let mut set = HashSet::new();
        set.insert(id1);
        assert!(set.contains(&id2));
        assert!(!set.contains(&id3));
    }

    #[test]
    fn test_coordinator_id_hashmap_key() {
        let id = CoordinatorId::new([0x42; 32]);
        let mut map = HashMap::new();
        map.insert(id, "value");

        assert_eq!(map.get(&id), Some(&"value"));
    }

    #[test]
    fn test_coordinator_id_display() {
        let id = CoordinatorId::new([0x42; 32]);
        let display = format!("{}", id);
        assert!(display.starts_with("CoordinatorId("));
        assert!(display.contains("..."));
    }

    #[test]
    fn test_coordinator_id_debug() {
        let id = CoordinatorId::new([0x42; 32]);
        let debug = format!("{:?}", id);
        assert!(debug.contains("CoordinatorId"));
    }

    #[test]
    fn test_coordinator_id_serde() {
        let id = CoordinatorId::new([0x42; 32]);
        let serialized = serde_json::to_string(&id).unwrap();
        let deserialized: CoordinatorId = serde_json::from_str(&serialized).unwrap();
        assert_eq!(id, deserialized);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // VALIDATOR ID TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validator_id_new() {
        let bytes = [0x42u8; 32];
        let id = ValidatorId::new(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn test_validator_id_from_bytes_valid() {
        let bytes = [0x42u8; 32];
        let id = ValidatorId::from_bytes(&bytes);
        assert!(id.is_some());
    }

    #[test]
    fn test_validator_id_from_bytes_invalid() {
        let bytes = [0x42u8; 16];
        let id = ValidatorId::from_bytes(&bytes);
        assert!(id.is_none());
    }

    #[test]
    fn test_validator_id_hex_roundtrip() {
        let original = ValidatorId::new([0x42; 32]);
        let hex = original.to_hex();
        let recovered = ValidatorId::from_hex(&hex).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_validator_id_from_hex_error() {
        let result = ValidatorId::from_hex("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_validator_id_hashmap_key() {
        let id = ValidatorId::new([0x42; 32]);
        let mut map = HashMap::new();
        map.insert(id, "value");
        assert_eq!(map.get(&id), Some(&"value"));
    }

    #[test]
    fn test_validator_id_serde() {
        let id = ValidatorId::new([0x42; 32]);
        let serialized = serde_json::to_string(&id).unwrap();
        let deserialized: ValidatorId = serde_json::from_str(&serialized).unwrap();
        assert_eq!(id, deserialized);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // WORKLOAD ID TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_workload_id_new() {
        let bytes = [0x42u8; 32];
        let id = WorkloadId::new(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn test_workload_id_from_bytes_valid() {
        let bytes = [0x42u8; 32];
        let id = WorkloadId::from_bytes(&bytes);
        assert!(id.is_some());
    }

    #[test]
    fn test_workload_id_from_bytes_invalid() {
        let bytes = [0x42u8; 16];
        let id = WorkloadId::from_bytes(&bytes);
        assert!(id.is_none());
    }

    #[test]
    fn test_workload_id_hex_roundtrip() {
        let original = WorkloadId::new([0x42; 32]);
        let hex = original.to_hex();
        let recovered = WorkloadId::from_hex(&hex).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_workload_id_from_hex_error() {
        let result = WorkloadId::from_hex("xyz");
        assert!(result.is_err());
    }

    #[test]
    fn test_workload_id_hashmap_key() {
        let id = WorkloadId::new([0x42; 32]);
        let mut map = HashMap::new();
        map.insert(id, "value");
        assert_eq!(map.get(&id), Some(&"value"));
    }

    #[test]
    fn test_workload_id_serde() {
        let id = WorkloadId::new([0x42; 32]);
        let serialized = serde_json::to_string(&id).unwrap();
        let deserialized: WorkloadId = serde_json::from_str(&serialized).unwrap();
        assert_eq!(id, deserialized);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // TIMESTAMP TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_timestamp_is_u64() {
        let ts: Timestamp = 1234567890;
        let _x: u64 = ts; // Should compile - type alias
        assert_eq!(ts, 1234567890u64);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // DETERMINISM TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_to_hex_deterministic() {
        let id = CoordinatorId::new([0x42; 32]);
        let hex1 = id.to_hex();
        let hex2 = id.to_hex();
        assert_eq!(hex1, hex2);
    }

    #[test]
    fn test_to_hex_always_lowercase() {
        let id = CoordinatorId::new([0xAB; 32]);
        let hex = id.to_hex();
        assert_eq!(hex, hex.to_lowercase());
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<CoordinatorId>();
        assert_send_sync::<ValidatorId>();
        assert_send_sync::<WorkloadId>();
        assert_send_sync::<ParseError>();
    }
}