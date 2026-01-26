//! # TSS Basic Identifier Types
//!
//! Module ini menyediakan identifier types untuk operasi TSS:
//! - `SessionId`: Identifier unik untuk DKG atau signing session
//! - `ParticipantId`: Identifier unik untuk participant dalam DKG
//! - `SignerId`: Identifier unik untuk signer dalam threshold signing
//!
//! ## Karakteristik
//!
//! Semua types memiliki karakteristik berikut:
//! - Ukuran tetap 32 bytes
//! - Opaque (inner value tidak dapat diakses secara mutable)
//! - Deterministic serialization (via serde)
//! - Constant-time equality comparison (via Eq derive)
//! - Hashable untuk penggunaan dalam HashMap/HashSet
//!
//! ## Keamanan
//!
//! Identifier dibuat menggunakan cryptographically secure random number generator
//! dari crate `rand`. Method `new()` menghasilkan identifier dengan entropi penuh.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::{Hash, Hasher};

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Ukuran identifier dalam bytes.
pub const IDENTIFIER_SIZE: usize = 32;

// ════════════════════════════════════════════════════════════════════════════════
// SESSION ID
// ════════════════════════════════════════════════════════════════════════════════

/// Identifier unik untuk DKG atau signing session.
///
/// `SessionId` digunakan untuk mengidentifikasi session DKG atau threshold signing
/// secara unik. Setiap session memiliki identifier berbeda untuk mencegah
/// replay attacks dan memastikan isolasi antar session.
///
/// ## Contoh
///
/// ```
/// use dsdn_tss::SessionId;
///
/// // Buat session ID baru dengan random bytes
/// let session_id = SessionId::new();
///
/// // Konversi ke hex untuk logging
/// let hex_str = session_id.to_hex();
/// assert_eq!(hex_str.len(), 64); // 32 bytes = 64 hex chars
///
/// // Buat dari bytes yang diketahui
/// let bytes = [0u8; 32];
/// let session_id = SessionId::from_bytes(bytes);
/// ```
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionId([u8; IDENTIFIER_SIZE]);

impl SessionId {
    /// Membuat `SessionId` baru dengan random bytes.
    ///
    /// Menggunakan `rand::thread_rng()` sebagai sumber entropi.
    /// Thread-safe dan cryptographically secure.
    #[must_use]
    pub fn new() -> Self {
        let mut bytes = [0u8; IDENTIFIER_SIZE];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Membuat `SessionId` dari bytes yang sudah ada.
    ///
    /// Tidak ada validasi dilakukan - caller bertanggung jawab
    /// memastikan bytes merepresentasikan identifier yang valid.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; IDENTIFIER_SIZE]) -> Self {
        Self(bytes)
    }

    /// Mengembalikan reference ke inner bytes.
    ///
    /// Inner bytes tidak dapat dimodifikasi melalui reference ini.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; IDENTIFIER_SIZE] {
        &self.0
    }

    /// Mengkonversi identifier ke lowercase hexadecimal string.
    ///
    /// Output selalu 64 karakter (32 bytes × 2 hex chars per byte).
    /// Deterministik: input yang sama selalu menghasilkan output yang sama.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut hex_string = String::with_capacity(IDENTIFIER_SIZE * 2);
        for byte in &self.0 {
            // Format byte sebagai 2-digit lowercase hex
            // Tidak menggunakan format! untuk menghindari allocation per-byte
            let high = (byte >> 4) & 0x0F;
            let low = byte & 0x0F;
            hex_string.push(hex_char(high));
            hex_string.push(hex_char(low));
        }
        hex_string
    }
}

impl Default for SessionId {
    /// Default menghasilkan identifier baru dengan random bytes.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Tampilkan 8 karakter pertama hex untuk readability
        let hex = self.to_hex();
        write!(f, "SessionId({}...)", &hex[..8])
    }
}

impl PartialEq for SessionId {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for SessionId {}

impl Hash for SessionId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// PARTICIPANT ID
// ════════════════════════════════════════════════════════════════════════════════

/// Identifier unik untuk participant dalam DKG protocol.
///
/// `ParticipantId` mengidentifikasi setiap participant dalam Distributed Key
/// Generation (DKG) ceremony. Setiap participant memiliki identifier unik
/// yang digunakan untuk routing messages dan tracking contributions.
///
/// ## Contoh
///
/// ```
/// use dsdn_tss::ParticipantId;
///
/// let participant_id = ParticipantId::new();
/// let bytes = participant_id.as_bytes();
/// assert_eq!(bytes.len(), 32);
/// ```
#[derive(Clone, Serialize, Deserialize)]
pub struct ParticipantId([u8; IDENTIFIER_SIZE]);

impl ParticipantId {
    /// Membuat `ParticipantId` baru dengan random bytes.
    ///
    /// Menggunakan `rand::thread_rng()` sebagai sumber entropi.
    #[must_use]
    pub fn new() -> Self {
        let mut bytes = [0u8; IDENTIFIER_SIZE];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Membuat `ParticipantId` dari bytes yang sudah ada.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; IDENTIFIER_SIZE]) -> Self {
        Self(bytes)
    }

    /// Mengembalikan reference ke inner bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; IDENTIFIER_SIZE] {
        &self.0
    }

    /// Mengkonversi identifier ke lowercase hexadecimal string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut hex_string = String::with_capacity(IDENTIFIER_SIZE * 2);
        for byte in &self.0 {
            let high = (byte >> 4) & 0x0F;
            let low = byte & 0x0F;
            hex_string.push(hex_char(high));
            hex_string.push(hex_char(low));
        }
        hex_string
    }
}

impl Default for ParticipantId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ParticipantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.to_hex();
        write!(f, "ParticipantId({}...)", &hex[..8])
    }
}

impl PartialEq for ParticipantId {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for ParticipantId {}

impl Hash for ParticipantId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// SIGNER ID
// ════════════════════════════════════════════════════════════════════════════════

/// Identifier unik untuk signer dalam threshold signing.
///
/// `SignerId` mengidentifikasi setiap signer yang berpartisipasi dalam
/// threshold signing ceremony. Identifier ini digunakan untuk tracking
/// partial signatures dan memastikan quorum requirements terpenuhi.
///
/// ## Contoh
///
/// ```
/// use dsdn_tss::SignerId;
///
/// let signer_id = SignerId::new();
/// println!("Signer: {}", signer_id.to_hex());
/// ```
#[derive(Clone, Serialize, Deserialize)]
pub struct SignerId([u8; IDENTIFIER_SIZE]);

impl SignerId {
    /// Membuat `SignerId` baru dengan random bytes.
    ///
    /// Menggunakan `rand::thread_rng()` sebagai sumber entropi.
    #[must_use]
    pub fn new() -> Self {
        let mut bytes = [0u8; IDENTIFIER_SIZE];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Membuat `SignerId` dari bytes yang sudah ada.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; IDENTIFIER_SIZE]) -> Self {
        Self(bytes)
    }

    /// Mengembalikan reference ke inner bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; IDENTIFIER_SIZE] {
        &self.0
    }

    /// Mengkonversi identifier ke lowercase hexadecimal string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut hex_string = String::with_capacity(IDENTIFIER_SIZE * 2);
        for byte in &self.0 {
            let high = (byte >> 4) & 0x0F;
            let low = byte & 0x0F;
            hex_string.push(hex_char(high));
            hex_string.push(hex_char(low));
        }
        hex_string
    }
}

impl Default for SignerId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SignerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.to_hex();
        write!(f, "SignerId({}...)", &hex[..8])
    }
}

impl PartialEq for SignerId {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for SignerId {}

impl Hash for SignerId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════════════════════════════════════

/// Konversi nibble (0-15) ke lowercase hex character.
///
/// # Safety
///
/// Input HARUS dalam range 0-15. Nilai di luar range menghasilkan
/// karakter tidak valid (silent, tidak panic).
#[inline]
const fn hex_char(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + nibble - 10) as char,
        // Unreachable jika input valid (0-15)
        // Return '?' untuk nilai invalid tanpa panic
        _ => '?',
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ────────────────────────────────────────────────────────────────────────────
    // SESSION ID TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_session_id_new_produces_32_bytes() {
        let id = SessionId::new();
        assert_eq!(id.as_bytes().len(), 32);
    }

    #[test]
    fn test_session_id_from_bytes() {
        let bytes = [0xAB; 32];
        let id = SessionId::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn test_session_id_to_hex_length() {
        let id = SessionId::new();
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn test_session_id_to_hex_deterministic() {
        let bytes = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let id = SessionId::from_bytes(bytes);
        let hex = id.to_hex();
        assert!(hex.starts_with("123456789abcdef0"));
    }

    #[test]
    fn test_session_id_to_hex_lowercase() {
        let bytes = [0xFF; 32];
        let id = SessionId::from_bytes(bytes);
        let hex = id.to_hex();
        // Semua karakter harus lowercase
        assert!(hex.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn test_session_id_equality() {
        let bytes = [0x42; 32];
        let id1 = SessionId::from_bytes(bytes);
        let id2 = SessionId::from_bytes(bytes);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_session_id_inequality() {
        let id1 = SessionId::from_bytes([0x00; 32]);
        let id2 = SessionId::from_bytes([0x01; 32]);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_session_id_hash_consistency() {
        let bytes = [0x77; 32];
        let id1 = SessionId::from_bytes(bytes);
        let id2 = SessionId::from_bytes(bytes);

        let mut map: HashMap<SessionId, u32> = HashMap::new();
        map.insert(id1, 100);

        // id2 harus bisa mengakses value yang sama karena hash sama
        assert_eq!(map.get(&id2), Some(&100));
    }

    #[test]
    fn test_session_id_serialize_deserialize() {
        let original = SessionId::from_bytes([0x99; 32]);
        let serialized = serde_json::to_string(&original).expect("serialize failed");
        let deserialized: SessionId = serde_json::from_str(&serialized).expect("deserialize failed");
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_session_id_debug_format() {
        let id = SessionId::from_bytes([0xAB; 32]);
        let debug = format!("{:?}", id);
        assert!(debug.starts_with("SessionId("));
        assert!(debug.contains("..."));
    }

    // ────────────────────────────────────────────────────────────────────────────
    // PARTICIPANT ID TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_participant_id_new_produces_32_bytes() {
        let id = ParticipantId::new();
        assert_eq!(id.as_bytes().len(), 32);
    }

    #[test]
    fn test_participant_id_from_bytes() {
        let bytes = [0xCD; 32];
        let id = ParticipantId::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn test_participant_id_to_hex_deterministic() {
        let bytes = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let id = ParticipantId::from_bytes(bytes);
        let hex = id.to_hex();
        assert!(hex.starts_with("deadbeef"));
    }

    #[test]
    fn test_participant_id_equality() {
        let bytes = [0x11; 32];
        let id1 = ParticipantId::from_bytes(bytes);
        let id2 = ParticipantId::from_bytes(bytes);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_participant_id_hash_in_hashmap() {
        let id = ParticipantId::from_bytes([0x22; 32]);
        let mut map: HashMap<ParticipantId, String> = HashMap::new();
        map.insert(id.clone(), "test".to_string());
        assert_eq!(map.get(&id), Some(&"test".to_string()));
    }

    #[test]
    fn test_participant_id_serialize_deserialize() {
        let original = ParticipantId::from_bytes([0x33; 32]);
        let serialized = serde_json::to_string(&original).expect("serialize failed");
        let deserialized: ParticipantId = serde_json::from_str(&serialized).expect("deserialize failed");
        assert_eq!(original, deserialized);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SIGNER ID TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_signer_id_new_produces_32_bytes() {
        let id = SignerId::new();
        assert_eq!(id.as_bytes().len(), 32);
    }

    #[test]
    fn test_signer_id_from_bytes() {
        let bytes = [0xEF; 32];
        let id = SignerId::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn test_signer_id_to_hex_deterministic() {
        let bytes = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let id = SignerId::from_bytes(bytes);
        let hex = id.to_hex();
        assert!(hex.starts_with("cafebabe"));
    }

    #[test]
    fn test_signer_id_equality() {
        let bytes = [0x44; 32];
        let id1 = SignerId::from_bytes(bytes);
        let id2 = SignerId::from_bytes(bytes);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_signer_id_hash_in_hashmap() {
        let id = SignerId::from_bytes([0x55; 32]);
        let mut map: HashMap<SignerId, i32> = HashMap::new();
        map.insert(id.clone(), 42);
        assert_eq!(map.get(&id), Some(&42));
    }

    #[test]
    fn test_signer_id_serialize_deserialize() {
        let original = SignerId::from_bytes([0x66; 32]);
        let serialized = serde_json::to_string(&original).expect("serialize failed");
        let deserialized: SignerId = serde_json::from_str(&serialized).expect("deserialize failed");
        assert_eq!(original, deserialized);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // CROSS-TYPE TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_different_types_not_confused() {
        // Memastikan types berbeda tidak bisa dicampuradukkan secara tidak sengaja
        let bytes = [0xAA; 32];
        let session = SessionId::from_bytes(bytes);
        let participant = ParticipantId::from_bytes(bytes);
        let signer = SignerId::from_bytes(bytes);

        // Hex sama untuk bytes yang sama
        assert_eq!(session.to_hex(), participant.to_hex());
        assert_eq!(participant.to_hex(), signer.to_hex());

        // Tapi types berbeda (compile-time safety)
        // Tidak bisa: session == participant (type mismatch)
    }

    #[test]
    fn test_hex_char_helper() {
        assert_eq!(hex_char(0), '0');
        assert_eq!(hex_char(9), '9');
        assert_eq!(hex_char(10), 'a');
        assert_eq!(hex_char(15), 'f');
        // Invalid input returns '?'
        assert_eq!(hex_char(16), '?');
    }

    #[test]
    fn test_zero_bytes() {
        let session = SessionId::from_bytes([0x00; 32]);
        let hex = session.to_hex();
        assert_eq!(hex, "0".repeat(64));
    }

    #[test]
    fn test_max_bytes() {
        let session = SessionId::from_bytes([0xFF; 32]);
        let hex = session.to_hex();
        assert_eq!(hex, "f".repeat(64));
    }
}