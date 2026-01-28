//! # TSS Basic Wrapper Types
//!
//! Module ini menyediakan wrapper types untuk raw bytes dalam TSS protocol.
//!
//! ## Types
//!
//! | Type | Size | Description |
//! |------|------|-------------|
//! | `BytesWrapper` | 32 bytes | Generic 32-byte wrapper (identifiers, hashes) |
//! | `SignatureBytes` | 64 bytes | Signature wrapper (FROST signatures) |
//!
//! ## Design Principles
//!
//! Semua wrapper types mengikuti prinsip berikut:
//! - Explicit length validation (tidak auto-fix atau pad)
//! - Deterministic serialization
//! - No panic, no unwrap
//! - Memory safe

use serde::{Deserialize, Serialize};

// ════════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════════

/// Expected byte length for BytesWrapper.
pub const BYTES_WRAPPER_SIZE: usize = 32;

/// Expected byte length for SignatureBytes.
pub const SIGNATURE_BYTES_SIZE: usize = 64;

// ════════════════════════════════════════════════════════════════════════════════
// BYTES WRAPPER (32 bytes)
// ════════════════════════════════════════════════════════════════════════════════

/// Generic 32-byte wrapper for identifiers, hashes, and other fixed-size data.
///
/// `BytesWrapper` is used for:
/// - Coordinator identifiers
/// - Validator identifiers
/// - Cryptographic hashes (SHA3-256)
/// - Public key representations
///
/// ## Invariants
///
/// - Inner `Vec<u8>` dapat memiliki panjang arbitrary
/// - Conversion ke/dari `[u8; 32]` memerlukan panjang tepat 32 bytes
/// - Tidak ada auto-padding atau truncation
///
/// ## Example
///
/// ```rust,ignore
/// use dsdn_proto::tss::BytesWrapper;
///
/// // Create from array
/// let bytes = BytesWrapper::from_array([0u8; 32]);
/// assert_eq!(bytes.as_slice().len(), 32);
///
/// // Convert back to array
/// let arr = bytes.to_array();
/// assert!(arr.is_some());
/// assert_eq!(arr.unwrap(), [0u8; 32]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BytesWrapper(Vec<u8>);

impl BytesWrapper {
    /// Creates a new `BytesWrapper` from a 32-byte array.
    ///
    /// # Arguments
    ///
    /// * `arr` - Exactly 32 bytes
    ///
    /// # Returns
    ///
    /// A `BytesWrapper` containing exactly 32 bytes.
    ///
    /// # Note
    ///
    /// This function is infallible as input is guaranteed to be 32 bytes.
    #[must_use]
    pub fn from_array(arr: [u8; BYTES_WRAPPER_SIZE]) -> Self {
        Self(arr.to_vec())
    }

    /// Creates a new `BytesWrapper` from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Arbitrary bytes
    ///
    /// # Note
    ///
    /// No length validation is performed. Use `to_array()` to validate
    /// if conversion to fixed-size array is needed.
    #[must_use]
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the inner bytes as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns the length of inner bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if inner bytes are empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Attempts to convert to a 32-byte array.
    ///
    /// # Returns
    ///
    /// - `Some([u8; 32])` if inner length is exactly 32 bytes
    /// - `None` if inner length is not 32 bytes
    ///
    /// # Note
    ///
    /// This function does NOT:
    /// - Truncate if too long
    /// - Pad if too short
    /// - Panic under any circumstances
    #[must_use]
    pub fn to_array(&self) -> Option<[u8; BYTES_WRAPPER_SIZE]> {
        if self.0.len() != BYTES_WRAPPER_SIZE {
            return None;
        }

        let mut arr = [0u8; BYTES_WRAPPER_SIZE];
        arr.copy_from_slice(&self.0);
        Some(arr)
    }

    /// Consumes self and returns the inner Vec.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl Default for BytesWrapper {
    fn default() -> Self {
        Self(vec![0u8; BYTES_WRAPPER_SIZE])
    }
}

impl AsRef<[u8]> for BytesWrapper {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// SIGNATURE BYTES (64 bytes)
// ════════════════════════════════════════════════════════════════════════════════

/// 64-byte wrapper for cryptographic signatures.
///
/// `SignatureBytes` is used for:
/// - FROST aggregate signatures (R || s format)
/// - EdDSA signatures
/// - Other 64-byte signature schemes
///
/// ## Invariants
///
/// - Inner `Vec<u8>` dapat memiliki panjang arbitrary
/// - Conversion ke/dari `[u8; 64]` memerlukan panjang tepat 64 bytes
/// - Tidak ada auto-padding atau truncation
///
/// ## Example
///
/// ```rust,ignore
/// use dsdn_proto::tss::SignatureBytes;
///
/// // Create from array
/// let sig = SignatureBytes::from_array([0u8; 64]);
/// assert_eq!(sig.as_slice().len(), 64);
///
/// // Convert back to array
/// let arr = sig.to_array();
/// assert!(arr.is_some());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureBytes(Vec<u8>);

impl SignatureBytes {
    /// Creates a new `SignatureBytes` from a 64-byte array.
    ///
    /// # Arguments
    ///
    /// * `arr` - Exactly 64 bytes
    ///
    /// # Returns
    ///
    /// A `SignatureBytes` containing exactly 64 bytes.
    ///
    /// # Note
    ///
    /// This function is infallible as input is guaranteed to be 64 bytes.
    #[must_use]
    pub fn from_array(arr: [u8; SIGNATURE_BYTES_SIZE]) -> Self {
        Self(arr.to_vec())
    }

    /// Creates a new `SignatureBytes` from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Arbitrary bytes
    ///
    /// # Note
    ///
    /// No length validation is performed. Use `to_array()` to validate
    /// if conversion to fixed-size array is needed.
    #[must_use]
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the inner bytes as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns the length of inner bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if inner bytes are empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Attempts to convert to a 64-byte array.
    ///
    /// # Returns
    ///
    /// - `Some([u8; 64])` if inner length is exactly 64 bytes
    /// - `None` if inner length is not 64 bytes
    ///
    /// # Note
    ///
    /// This function does NOT:
    /// - Truncate if too long
    /// - Pad if too short
    /// - Panic under any circumstances
    #[must_use]
    pub fn to_array(&self) -> Option<[u8; SIGNATURE_BYTES_SIZE]> {
        if self.0.len() != SIGNATURE_BYTES_SIZE {
            return None;
        }

        let mut arr = [0u8; SIGNATURE_BYTES_SIZE];
        arr.copy_from_slice(&self.0);
        Some(arr)
    }

    /// Consumes self and returns the inner Vec.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl Default for SignatureBytes {
    fn default() -> Self {
        Self(vec![0u8; SIGNATURE_BYTES_SIZE])
    }
}

impl AsRef<[u8]> for SignatureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────────────────────
    // BYTES WRAPPER TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_bytes_wrapper_from_array() {
        let arr = [0xABu8; 32];
        let wrapper = BytesWrapper::from_array(arr);
        assert_eq!(wrapper.len(), 32);
        assert_eq!(wrapper.as_slice(), &arr);
    }

    #[test]
    fn test_bytes_wrapper_to_array_valid() {
        let arr = [0xCDu8; 32];
        let wrapper = BytesWrapper::from_array(arr);
        let result = wrapper.to_array();
        assert!(result.is_some());
        assert_eq!(result.expect("valid"), arr);
    }

    #[test]
    fn test_bytes_wrapper_to_array_too_short() {
        let wrapper = BytesWrapper::from_vec(vec![0u8; 16]);
        assert!(wrapper.to_array().is_none());
    }

    #[test]
    fn test_bytes_wrapper_to_array_too_long() {
        let wrapper = BytesWrapper::from_vec(vec![0u8; 64]);
        assert!(wrapper.to_array().is_none());
    }

    #[test]
    fn test_bytes_wrapper_to_array_empty() {
        let wrapper = BytesWrapper::from_vec(vec![]);
        assert!(wrapper.to_array().is_none());
        assert!(wrapper.is_empty());
    }

    #[test]
    fn test_bytes_wrapper_default() {
        let wrapper = BytesWrapper::default();
        assert_eq!(wrapper.len(), 32);
        assert!(wrapper.to_array().is_some());
    }

    #[test]
    fn test_bytes_wrapper_into_vec() {
        let arr = [0xEFu8; 32];
        let wrapper = BytesWrapper::from_array(arr);
        let vec = wrapper.into_vec();
        assert_eq!(vec.len(), 32);
        assert_eq!(vec.as_slice(), &arr);
    }

    #[test]
    fn test_bytes_wrapper_equality() {
        let w1 = BytesWrapper::from_array([0x11u8; 32]);
        let w2 = BytesWrapper::from_array([0x11u8; 32]);
        let w3 = BytesWrapper::from_array([0x22u8; 32]);
        assert_eq!(w1, w2);
        assert_ne!(w1, w3);
    }

    #[test]
    fn test_bytes_wrapper_serialize_deserialize() {
        let original = BytesWrapper::from_array([0x99u8; 32]);
        let json = serde_json::to_string(&original).expect("serialize");
        let recovered: BytesWrapper = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, recovered);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SIGNATURE BYTES TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_signature_bytes_from_array() {
        let arr = [0xABu8; 64];
        let sig = SignatureBytes::from_array(arr);
        assert_eq!(sig.len(), 64);
        assert_eq!(sig.as_slice(), &arr);
    }

    #[test]
    fn test_signature_bytes_to_array_valid() {
        let arr = [0xCDu8; 64];
        let sig = SignatureBytes::from_array(arr);
        let result = sig.to_array();
        assert!(result.is_some());
        assert_eq!(result.expect("valid"), arr);
    }

    #[test]
    fn test_signature_bytes_to_array_too_short() {
        let sig = SignatureBytes::from_vec(vec![0u8; 32]);
        assert!(sig.to_array().is_none());
    }

    #[test]
    fn test_signature_bytes_to_array_too_long() {
        let sig = SignatureBytes::from_vec(vec![0u8; 128]);
        assert!(sig.to_array().is_none());
    }

    #[test]
    fn test_signature_bytes_to_array_empty() {
        let sig = SignatureBytes::from_vec(vec![]);
        assert!(sig.to_array().is_none());
        assert!(sig.is_empty());
    }

    #[test]
    fn test_signature_bytes_default() {
        let sig = SignatureBytes::default();
        assert_eq!(sig.len(), 64);
        assert!(sig.to_array().is_some());
    }

    #[test]
    fn test_signature_bytes_into_vec() {
        let arr = [0xEFu8; 64];
        let sig = SignatureBytes::from_array(arr);
        let vec = sig.into_vec();
        assert_eq!(vec.len(), 64);
        assert_eq!(vec.as_slice(), &arr);
    }

    #[test]
    fn test_signature_bytes_equality() {
        let s1 = SignatureBytes::from_array([0x11u8; 64]);
        let s2 = SignatureBytes::from_array([0x11u8; 64]);
        let s3 = SignatureBytes::from_array([0x22u8; 64]);
        assert_eq!(s1, s2);
        assert_ne!(s1, s3);
    }

    #[test]
    fn test_signature_bytes_serialize_deserialize() {
        let original = SignatureBytes::from_array([0x99u8; 64]);
        let json = serde_json::to_string(&original).expect("serialize");
        let recovered: SignatureBytes = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, recovered);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // SEND + SYNC TESTS
    // ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BytesWrapper>();
        assert_send_sync::<SignatureBytes>();
    }
}