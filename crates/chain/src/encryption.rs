//! # File Encryption Module (13.17.5)
//!
//! Cryptographic file encryption dan key wrapping untuk DSDN.
//!
//! ## Overview
//!
//! Module ini menyediakan:
//! - AES-256-GCM authenticated encryption untuk file
//! - X25519 key exchange untuk file key sharing
//! - Deterministic key derivation terikat ke Wallet
//!
//! ## Security Properties
//!
//! ```text
//! ⚠️ CRITICAL SECURITY:
//! - Menggunakan HANYA AES-256-GCM (authenticated encryption)
//! - Nonce WAJIB random 12 bytes untuk setiap enkripsi
//! - Authentication tag WAJIB diverifikasi saat decrypt
//! - Key derivation deterministik dengan context separation
//! - Key wrapping menggunakan X25519 ECDH
//! ```
//!
//! ## Cryptographic Choices
//!
//! | Component | Algorithm | Size |
//! |-----------|-----------|------|
//! | Symmetric Encryption | AES-256-GCM | 256-bit key |
//! | Nonce | Random | 96-bit (12 bytes) |
//! | Auth Tag | GCM Tag | 128-bit (16 bytes) |
//! | Key Derivation | SHA3-256 | 256-bit output |
//! | Key Exchange | X25519 | 256-bit shared secret |
//!
//! ## NOT Provided
//!
//! - Storage backend
//! - RPC/CLI integration
//! - Key rotation
//! - Multi-party encryption

// ════════════════════════════════════════════════════════════════════════════════
// ENCRYPTED FILE STRUCT (13.17.5)
// ════════════════════════════════════════════════════════════════════════════════
// Represents encrypted file data with authenticated encryption.
//
// INVARIANTS:
// - nonce MUST be 12 bytes (AES-GCM standard)
// - tag MUST be 16 bytes (128-bit authentication)
// - ciphertext length = plaintext length (no padding in GCM)
// ════════════════════════════════════════════════════════════════════════════════

/// Encrypted file container dengan AES-256-GCM.
///
/// Berisi semua data yang diperlukan untuk decrypt:
/// - Nonce untuk counter mode
/// - Ciphertext hasil enkripsi
/// - Tag untuk authentication verification
#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedFile {
    /// 96-bit nonce (AES-GCM standard)
    /// WAJIB unique untuk setiap enkripsi dengan key yang sama
    pub nonce: [u8; 12],
    
    /// Ciphertext hasil AES-256-GCM encryption
    /// Panjang = panjang plaintext (no padding)
    pub ciphertext: Vec<u8>,
    
    /// 128-bit authentication tag
    /// WAJIB diverifikasi sebelum plaintext dianggap valid
    pub tag: [u8; 16],
}

impl EncryptedFile {
    /// Create new EncryptedFile dari komponen.
    ///
    /// # Arguments
    /// * `nonce` - 12-byte nonce
    /// * `ciphertext` - Encrypted data
    /// * `tag` - 16-byte authentication tag
    #[inline]
    pub fn new(nonce: [u8; 12], ciphertext: Vec<u8>, tag: [u8; 16]) -> Self {
        Self {
            nonce,
            ciphertext,
            tag,
        }
    }
    
    /// Get nonce bytes.
    #[inline]
    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }
    
    /// Get ciphertext bytes.
    #[inline]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    
    /// Get authentication tag.
    #[inline]
    pub fn tag(&self) -> &[u8; 16] {
        &self.tag
    }
    
    /// Total size in bytes (nonce + ciphertext + tag).
    #[inline]
    pub fn total_size(&self) -> usize {
        12 + self.ciphertext.len() + 16
    }
    
    /// Serialize ke bytes: nonce || ciphertext || tag
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.total_size());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes.extend_from_slice(&self.tag);
        bytes
    }
    
    /// Deserialize dari bytes.
    ///
    /// Format: nonce (12) || ciphertext (variable) || tag (16)
    /// Minimum length: 28 bytes (empty ciphertext)
    ///
    /// # Returns
    /// * `Some(EncryptedFile)` - Valid deserialization
    /// * `None` - Invalid format atau length
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        // Minimum: 12 (nonce) + 0 (ciphertext) + 16 (tag) = 28
        if bytes.len() < 28 {
            return None;
        }
        
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[0..12]);
        
        let ciphertext_len = bytes.len() - 28;
        let ciphertext = bytes[12..12 + ciphertext_len].to_vec();
        
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&bytes[bytes.len() - 16..]);
        
        Some(Self {
            nonce,
            ciphertext,
            tag,
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// FILE KEY STRUCT (13.17.5)
// ════════════════════════════════════════════════════════════════════════════════
// Represents a file encryption key with optional wrapped version for sharing.
//
// INVARIANTS:
// - key MUST be 32 bytes (AES-256)
// - wrapped_key MUST NOT be empty when sharing
// ════════════════════════════════════════════════════════════════════════════════

/// File encryption key dengan wrapped version untuk sharing.
///
/// Digunakan untuk:
/// - Enkripsi file dengan key dedicated (bukan derived dari wallet)
/// - Sharing encrypted file ke recipient lain
#[derive(Clone)]
pub struct FileKey {
    /// 256-bit file encryption key
    pub key: [u8; 32],
    
    /// Wrapped key untuk recipient (encrypted dengan shared secret)
    /// Format: ephemeral_pubkey (32) || encrypted_key (32) || tag (16)
    pub wrapped_key: Vec<u8>,
}

impl FileKey {
    /// Create new FileKey dari raw key.
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    #[inline]
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            wrapped_key: Vec::new(),
        }
    }
    
    /// Create FileKey dengan wrapped version.
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    /// * `wrapped_key` - Encrypted key untuk recipient
    #[inline]
    pub fn with_wrapped(key: [u8; 32], wrapped_key: Vec<u8>) -> Self {
        Self {
            key,
            wrapped_key,
        }
    }
    
    /// Check if key has been wrapped untuk sharing.
    #[inline]
    pub fn is_wrapped(&self) -> bool {
        !self.wrapped_key.is_empty()
    }
    
    /// Get wrapped key bytes.
    #[inline]
    pub fn wrapped(&self) -> &[u8] {
        &self.wrapped_key
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// DEBUG IMPLEMENTATION (SAFE - NEVER EXPOSE KEY)
// ════════════════════════════════════════════════════════════════════════════════

impl std::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // HANYA show wrapped status, TIDAK PERNAH raw key
        f.debug_struct("FileKey")
            .field("is_wrapped", &self.is_wrapped())
            .field("wrapped_key_len", &self.wrapped_key.len())
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS (13.17.5)
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypted_file_new() {
        let nonce = [1u8; 12];
        let ciphertext = vec![2u8; 100];
        let tag = [3u8; 16];
        
        let encrypted = EncryptedFile::new(nonce, ciphertext.clone(), tag);
        
        assert_eq!(encrypted.nonce(), &nonce);
        assert_eq!(encrypted.ciphertext(), &ciphertext[..]);
        assert_eq!(encrypted.tag(), &tag);
        assert_eq!(encrypted.total_size(), 12 + 100 + 16);
        
        println!("✅ test_encrypted_file_new PASSED");
    }
    
    #[test]
    fn test_encrypted_file_serialization() {
        let nonce = [0xAAu8; 12];
        let ciphertext = vec![0xBBu8; 50];
        let tag = [0xCCu8; 16];
        
        let original = EncryptedFile::new(nonce, ciphertext, tag);
        let bytes = original.to_bytes();
        
        // Verify length
        assert_eq!(bytes.len(), 12 + 50 + 16);
        
        // Deserialize
        let restored = EncryptedFile::from_bytes(&bytes);
        assert!(restored.is_some());
        
        let restored = restored.unwrap();
        assert_eq!(original, restored);
        
        println!("✅ test_encrypted_file_serialization PASSED");
    }
    
    #[test]
    fn test_encrypted_file_from_bytes_invalid() {
        // Too short
        let short = vec![0u8; 27];
        assert!(EncryptedFile::from_bytes(&short).is_none());
        
        // Minimum valid (empty ciphertext)
        let min = vec![0u8; 28];
        let result = EncryptedFile::from_bytes(&min);
        assert!(result.is_some());
        assert_eq!(result.unwrap().ciphertext().len(), 0);
        
        println!("✅ test_encrypted_file_from_bytes_invalid PASSED");
    }
    
    #[test]
    fn test_file_key_new() {
        let key = [0x42u8; 32];
        let file_key = FileKey::new(key);
        
        assert_eq!(file_key.key, key);
        assert!(!file_key.is_wrapped());
        assert!(file_key.wrapped().is_empty());
        
        println!("✅ test_file_key_new PASSED");
    }
    
    #[test]
    fn test_file_key_with_wrapped() {
        let key = [0x42u8; 32];
        let wrapped = vec![0xFFu8; 80];
        
        let file_key = FileKey::with_wrapped(key, wrapped.clone());
        
        assert_eq!(file_key.key, key);
        assert!(file_key.is_wrapped());
        assert_eq!(file_key.wrapped(), &wrapped[..]);
        
        println!("✅ test_file_key_with_wrapped PASSED");
    }
    
    #[test]
    fn test_file_key_debug_no_leak() {
        let key = [0x42u8; 32];
        let file_key = FileKey::new(key);
        
        let debug_str = format!("{:?}", file_key);
        
        // Debug harus contain is_wrapped
        assert!(debug_str.contains("is_wrapped"));
        
        // Debug TIDAK BOLEH contain raw key bytes
        let key_hex = hex::encode(&key);
        assert!(!debug_str.contains(&key_hex));
        
        println!("✅ test_file_key_debug_no_leak PASSED");
    }
}