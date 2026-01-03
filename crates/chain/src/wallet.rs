//! # Wallet Module (13.17.1)
//!
//! High-level wallet API untuk DSDN blockchain.
//!
//! ## Overview
//!
//! Module ini menyediakan abstraksi aman untuk:
//! - Ed25519 keypair generation
//! - Key restoration dari secret atau full keypair
//! - Address derivation (konsisten dengan chain rules)
//! - Key export untuk backup/storage
//!
//! ## Security Notes
//!
//! ```text
//! ⚠️ CRITICAL SECURITY:
//! - secret_key TIDAK BOLEH di-log atau di-display
//! - keypair_bytes mengandung secret material
//! - export_secret_hex() HANYA untuk backup
//! - Semua crypto operations menggunakan ed25519-dalek
//! ```
//!
//! ## Relationship with Chain
//!
//! ```text
//! Wallet → public_key → Address → ChainState
//!                                     │
//!                                     ├── balances[address]
//!                                     ├── nonces[address]
//!                                     └── locked[address]
//! ```
//!
//! ## Guarantees
//!
//! - NO PANIC: Semua error di-handle gracefully
//! - DETERMINISTIC: Same input → same output
//! - CONSISTENT: Address derivation sama dengan chain
//! - SAFE: Secret key tidak pernah leak via Debug/Display
//!
//! ## Signing (13.17.2)
//!
//! - sign_message() → Sign arbitrary bytes
//! - sign_tx() → Sign TxEnvelope payload
//! - verify_signature() → Verify signature dengan public key sendiri
//!
//! ## NOT Provided (Tahap Berikutnya)
//!
//! - File encryption → 13.17.5
//! - RPC/CLI integration → 13.17.8

use crate::types::Address;
use crate::crypto::{generate_ed25519_keypair_bytes, address_from_pubkey_bytes, sign_message_with_keypair_bytes};
use crate::tx::TxEnvelope;
use crate::encryption::EncryptedFile;
use crate::celestia::BlobCommitment;

// ════════════════════════════════════════════════════════════════════════════════
// WALLET ERROR (13.17.2)
// ════════════════════════════════════════════════════════════════════════════════
// Error types untuk wallet operations.
// Digunakan untuk signing dan transaction building.
// ════════════════════════════════════════════════════════════════════════════════

/// Error types untuk Wallet operations.
///
/// Digunakan untuk menangani error pada signing dan transaction building
/// tanpa panic.
#[derive(Debug, Clone, PartialEq)]
pub enum WalletError {
    /// Signing operation gagal
    SigningFailed(String),
    
    /// Panjang key tidak valid (bukan 32 atau 64 bytes)
    InvalidKeyLength,
    
    /// Serialization payload gagal
    SerializationError(String),
    
    // ════════════════════════════════════════════════════════════════════════════
    // ENCRYPTION ERRORS (13.17.5)
    // ════════════════════════════════════════════════════════════════════════════
    
    /// Encryption operation gagal (AES-GCM error)
    EncryptionFailed,
    
    /// Decryption operation gagal
    DecryptionFailed,
    
    /// Ciphertext format atau panjang tidak valid
    InvalidCiphertext,
    
    /// Authentication tag verification gagal
    /// Indicates tampering atau wrong key
    AuthenticationFailed,
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletError::SigningFailed(msg) => write!(f, "signing failed: {}", msg),
            WalletError::InvalidKeyLength => write!(f, "invalid key length"),
            WalletError::SerializationError(msg) => write!(f, "serialization error: {}", msg),
            WalletError::EncryptionFailed => write!(f, "encryption failed"),
            WalletError::DecryptionFailed => write!(f, "decryption failed"),
            WalletError::InvalidCiphertext => write!(f, "invalid ciphertext"),
            WalletError::AuthenticationFailed => write!(f, "authentication failed"),
        }
    }
}

impl std::error::Error for WalletError {}

// ════════════════════════════════════════════════════════════════════════════════
// WALLET STRUCT (13.17.1)
// ════════════════════════════════════════════════════════════════════════════════
// Core wallet structure containing Ed25519 keypair and derived address.
//
// INVARIANTS (WAJIB TERJAGA):
// - keypair_bytes[0..32] = secret key (32 bytes)
// - keypair_bytes[32..64] = public key (32 bytes)
// - public_key == keypair_bytes[32..64]
// - address = address_from_pubkey_bytes(public_key)
// ════════════════════════════════════════════════════════════════════════════════

/// Wallet merepresentasikan identitas kriptografis user di DSDN.
///
/// Berisi Ed25519 keypair dan derived blockchain address.
/// Semua operasi deterministik dan tidak akan panic.
#[derive(Clone)]
pub struct Wallet {
    /// Full Ed25519 keypair: secret (32 bytes) + public (32 bytes)
    /// CRITICAL: Bytes [0..32] adalah SECRET KEY
    keypair_bytes: [u8; 64],
    
    /// Public key extracted dari keypair (untuk convenience)
    /// INVARIANT: Harus identik dengan keypair_bytes[32..64]
    public_key: [u8; 32],
    
    /// Blockchain address derived dari public key
    /// INVARIANT: Harus konsisten dengan chain address derivation
    address: Address,
}

// ════════════════════════════════════════════════════════════════════════════════
// CONSTRUCTOR METHODS
// ════════════════════════════════════════════════════════════════════════════════

impl Wallet {
    /// Generate wallet baru dengan random Ed25519 keypair.
    ///
    /// Menggunakan cryptographically secure RNG (via ed25519-dalek).
    /// Address di-derive secara deterministik dari public key.
    ///
    /// # Returns
    /// Wallet instance baru dengan fresh keypair.
    ///
    /// # Example
    /// ```rust,ignore
    /// let wallet = Wallet::generate();
    /// println!("New address: {:?}", wallet.address());
    /// ```
    ///
    /// # Notes
    /// - Menggunakan HANYA `generate_ed25519_keypair_bytes()` dari crypto module
    /// - Tidak ada manual key generation
    /// - Tidak mengubah urutan bytes
    pub fn generate() -> Self {
        // Generate keypair menggunakan chain's crypto module
        // Returns: (pubkey_vec: Vec<u8>, keypair_bytes: [u8; 64])
        let (pubkey_vec, keypair_vec) = generate_ed25519_keypair_bytes();

        // Validasi panjang (SECURITY CRITICAL)
        assert_eq!(keypair_vec.len(), 64, "invalid keypair length");

        let mut keypair_bytes = [0u8; 64];
        keypair_bytes.copy_from_slice(&keypair_vec);

        
        // Extract public key dari keypair_bytes[32..64]
        // SAFETY: keypair_bytes selalu 64 bytes dari generate_ed25519_keypair_bytes
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&keypair_bytes[32..64]);
        
        // Derive address dari public key menggunakan chain's address derivation
        // Fallback ke zero address jika derivation gagal (seharusnya tidak terjadi)
        let address = match address_from_pubkey_bytes(&pubkey_vec) {
            Ok(addr) => addr,
            Err(_) => Address::from_bytes([0u8; 20]),
        };
        
        Self {
            keypair_bytes,
            public_key,
            address,
        }
    }
    
    /// Restore wallet dari 32-byte secret key.
    ///
    /// Derive public key dari secret key menggunakan Ed25519 scalar multiplication.
    /// Address di-derive secara deterministik dari public key.
    ///
    /// # Arguments
    /// * `secret` - 32-byte Ed25519 secret key
    ///
    /// # Returns
    /// Wallet instance dengan keypair derived dari secret.
    ///
    /// # Example
    /// ```rust,ignore
    /// let secret: [u8; 32] = /* from backup */;
    /// let wallet = Wallet::from_secret_key(&secret);
    /// ```
    ///
    /// # Notes
    /// - Derive public key dari secret key
    /// - Construct full [u8; 64] keypair
    /// - Public key konsisten dengan Ed25519 derivation
    /// - Tidak panic
    pub fn from_secret_key(secret: &[u8; 32]) -> Self {
        use ed25519_dalek::{SecretKey, PublicKey};

        let secret_key = SecretKey::from_bytes(secret)
            .expect("32-byte secret key");

        let public_key: PublicKey = (&secret_key).into();
        let public_key_bytes = public_key.to_bytes();

        
        // Construct full keypair bytes: secret (32) + public (32)
        let mut keypair_bytes = [0u8; 64];
        keypair_bytes[0..32].copy_from_slice(secret);
        keypair_bytes[32..64].copy_from_slice(&public_key_bytes);
        
        // Derive address dari public key
        let address = match address_from_pubkey_bytes(&public_key_bytes.to_vec()) {
            Ok(addr) => addr,
            Err(_) => Address::from_bytes([0u8; 20]),
        };
        
        Self {
            keypair_bytes,
            public_key: public_key_bytes,
            address,
        }
    }
    
    /// Restore wallet dari full 64-byte keypair.
    ///
    /// Format yang diharapkan: secret (32 bytes) + public (32 bytes).
    /// TIDAK regenerate public key - trust input.
    ///
    /// # Arguments
    /// * `keypair_bytes` - 64-byte Ed25519 keypair (secret + public)
    ///
    /// # Returns
    /// Wallet instance dengan provided keypair.
    ///
    /// # Example
    /// ```rust,ignore
    /// let backup: [u8; 64] = /* from export_keypair() */;
    /// let wallet = Wallet::from_bytes(&backup);
    /// ```
    ///
    /// # Notes
    /// - Ambil public key dari bytes [32..64]
    /// - Tidak regenerate key
    /// - Tidak reorder bytes
    /// - Validasi implicit via type system (compile-time length check)
    pub fn from_bytes(keypair_bytes: &[u8; 64]) -> Self {
        // Extract public key dari bytes [32..64]
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&keypair_bytes[32..64]);
        
        // Derive address dari public key
        let address = match address_from_pubkey_bytes(&public_key.to_vec()) {
            Ok(addr) => addr,
            Err(_) => Address::from_bytes([0u8; 20]),
        };
        
        Self {
            keypair_bytes: *keypair_bytes,
            public_key,
            address,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// GETTER METHODS
// ════════════════════════════════════════════════════════════════════════════════

impl Wallet {
    /// Get blockchain address derived dari wallet's public key.
    ///
    /// Address ini digunakan untuk:
    /// - Menerima transfer
    /// - Identifikasi account di state
    /// - Transaction sender verification
    ///
    /// # Returns
    /// Copy dari wallet's Address.
    #[inline]
    pub fn address(&self) -> Address {
        self.address
    }
    
    /// Get reference ke 32-byte public key.
    ///
    /// Public key aman untuk di-share dan digunakan untuk:
    /// - Signature verification
    /// - Address derivation
    /// - Identity dalam transactions
    ///
    /// # Returns
    /// Reference ke public key bytes.
    #[inline]
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
    
    /// Get reference ke 32-byte secret key.
    ///
    /// # Security Warning
    /// Secret key HARUS dijaga kerahasiaannya. Exposure menyebabkan:
    /// - Complete account takeover
    /// - Pencurian semua asset
    /// - Kerusakan irreversible
    ///
    /// # Returns
    /// Reference ke secret key bytes (first 32 bytes of keypair).
    #[inline]
    pub fn secret_key(&self) -> &[u8; 32] {
        // SAFETY: keypair_bytes selalu 64 bytes
        // First 32 bytes adalah secret key
        // Menggunakan array reference untuk zero-copy
        //
        // Equivalent to: &keypair_bytes[0..32] as &[u8; 32]
        // Tapi dengan compile-time guarantee
        // SAFETY: 
        // 1. keypair_bytes adalah [u8; 64], always valid
        // 2. ptr points to start of array
        // 3. We only read first 32 bytes which is within bounds
        // 4. Alignment is 1 for u8
        self.keypair_bytes[0..32]
            .try_into()
            .expect("keypair_bytes always 64 bytes")
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// EXPORT METHODS
// ════════════════════════════════════════════════════════════════════════════════

impl Wallet {
    /// Export full 64-byte keypair untuk backup.
    ///
    /// Format: secret (32 bytes) + public (32 bytes).
    /// Dapat di-restore via `Wallet::from_bytes()`.
    ///
    /// # Security Warning
    /// Ini mengandung secret key. Store securely!
    ///
    /// # Returns
    /// Copy dari full keypair bytes.
    #[inline]
    pub fn export_keypair(&self) -> [u8; 64] {
        self.keypair_bytes
    }
    
    /// Export secret key sebagai lowercase hexadecimal string.
    ///
    /// Format: 64 hex characters (32 bytes), tanpa prefix "0x".
    /// Dapat digunakan untuk text-based backup.
    ///
    /// # Security Warning
    /// Ini adalah secret key dalam plain text. Handle dengan sangat hati-hati!
    ///
    /// # Returns
    /// Lowercase hex string dari secret key.
    ///
    /// # Example
    /// ```rust,ignore
    /// let hex = wallet.export_secret_hex();
    /// // "a1b2c3d4..." (64 characters)
    /// ```
    pub fn export_secret_hex(&self) -> String {
        hex::encode(&self.keypair_bytes[0..32])
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// SIGNING METHODS (13.17.2)
// ════════════════════════════════════════════════════════════════════════════════
// Transaction dan message signing menggunakan Ed25519.
//
// FLOW:
// 1. sign_message() → Sign arbitrary bytes, return 64-byte signature
// 2. sign_tx() → Serialize payload, sign, return new TxEnvelope
// 3. verify_signature() → Verify signature dengan public key sendiri
//
// IMPORTANT:
// - Hanya payload yang di-sign, BUKAN seluruh envelope
// - Signature selalu 64 bytes (Ed25519)
// - Verification dilakukan oleh chain, bukan wallet
// ════════════════════════════════════════════════════════════════════════════════

impl Wallet {
    /// Sign arbitrary message bytes.
    ///
    /// Menggunakan Ed25519 signature scheme.
    /// Return 64-byte signature atau empty Vec jika gagal.
    ///
    /// # Arguments
    /// * `message` - Bytes yang akan di-sign
    ///
    /// # Returns
    /// 64-byte Ed25519 signature, atau empty Vec jika signing gagal.
    ///
    /// # Example
    /// ```rust,ignore
    /// let message = b"hello world";
    /// let signature = wallet.sign_message(message);
    /// assert_eq!(signature.len(), 64);
    /// ```
    ///
    /// # Notes
    /// - Menggunakan HANYA `sign_message_with_keypair_bytes()` dari crypto module
    /// - Tidak ada hashing manual
    /// - Tidak ada encoding tambahan
    /// - Return empty Vec jika gagal (tidak panic)
    pub fn sign_message(&self, message: &[u8]) -> Vec<u8> {
        // Gunakan chain's crypto module untuk signing
        // Return empty Vec jika gagal (tidak crash)
        match sign_message_with_keypair_bytes(&self.keypair_bytes, message) {
            Ok(signature) => signature,
            Err(_) => Vec::new(),
        }
    }
    
    /// Sign TxEnvelope dan return envelope baru dengan signature.
    ///
    /// ALUR:
    /// 1. Serialize payload transaksi untuk signing
    /// 2. Sign bytes payload
    /// 3. Inject signature ke TxEnvelope baru
    ///
    /// # Arguments
    /// * `tx` - TxEnvelope yang akan di-sign (tidak dimodifikasi)
    ///
    /// # Returns
    /// * `Ok(TxEnvelope)` - Envelope baru dengan signature terisi
    /// * `Err(WalletError)` - Jika serialization atau signing gagal
    ///
    /// # Example
    /// ```rust,ignore
    /// let unsigned_tx = TxEnvelope::new_unsigned(payload);
    /// let signed_tx = wallet.sign_tx(&unsigned_tx)?;
    /// ```
    ///
    /// # Notes
    /// - Input `tx` TIDAK dimodifikasi (immutable)
    /// - Hanya payload yang di-sign, bukan seluruh envelope
    /// - Public key di-inject ke envelope untuk verification
    pub fn sign_tx(&self, tx: &TxEnvelope) -> Result<TxEnvelope, WalletError> {
        // Step 1: Serialize payload untuk signing
        let payload_bytes = tx.payload_bytes()
            .map_err(|e| WalletError::SerializationError(format!("{}", e)))?;
        
        // Step 2: Sign payload bytes
        let signature = sign_message_with_keypair_bytes(&self.keypair_bytes, &payload_bytes)
            .map_err(|e| WalletError::SigningFailed(format!("{}", e)))?;
        
        // Validate signature length (MUST be 64 bytes)
        if signature.len() != 64 {
            return Err(WalletError::SigningFailed(
                format!("invalid signature length: {} (expected 64)", signature.len())
            ));
        }
        
        // Step 3: Create new envelope dengan signature
        let mut signed_tx = tx.clone();
        signed_tx.signature = signature;
        signed_tx.pubkey = self.public_key.to_vec();
        
        Ok(signed_tx)
    }
    
    /// Verify signature dengan public key milik wallet sendiri.
    ///
    /// # Arguments
    /// * `message` - Bytes yang telah di-sign
    /// * `signature` - Signature yang akan diverifikasi (64 bytes)
    ///
    /// # Returns
    /// * `true` - Signature valid
    /// * `false` - Signature invalid atau error
    ///
    /// # Example
    /// ```rust,ignore
    /// let message = b"hello world";
    /// let signature = wallet.sign_message(message);
    /// assert!(wallet.verify_signature(message, &signature));
    /// ```
    ///
    /// # Notes
    /// - Verify menggunakan public key milik wallet sendiri
    /// - Return false jika signature length != 64
    /// - Return false jika verification gagal
    /// - Tidak panic
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        use ed25519_dalek::{Signature, PublicKey, Verifier};

        if signature.len() != 64 {
            return false;
        }

        // Signature::from_bytes untuk ed25519-dalek 1.x
        let sig = match Signature::from_bytes(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // Gunakan PublicKey, BUKAN VerifyingKey
        let public_key = match PublicKey::from_bytes(&self.public_key) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        // Verify
        public_key.verify(message, &sig).is_ok()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// FILE ENCRYPTION METHODS (13.17.5)
// ════════════════════════════════════════════════════════════════════════════════
// Wallet-bound file encryption menggunakan AES-256-GCM.
//
// FLOW:
// 1. derive_encryption_key() → Derive key dari secret + context
// 2. encrypt_file() → Encrypt plaintext dengan derived key
// 3. decrypt_file() → Decrypt dan verify authentication tag
// 4. wrap_file_key() → Wrap key untuk sharing via X25519
// 5. unwrap_file_key() → Unwrap received key
//
// SECURITY:
// - Key derivation deterministik dengan context separation
// - AES-GCM provides authenticated encryption
// - X25519 provides forward secrecy untuk key sharing
// - Nonce selalu random 12 bytes
// ════════════════════════════════════════════════════════════════════════════════

impl Wallet {
    /// Derive 32-byte encryption key dari wallet secret dan context.
    ///
    /// Menggunakan SHA3-256(secret_key || context) untuk key derivation.
    /// Context memberikan domain separation untuk berbagai keperluan.
    ///
    /// # Arguments
    /// * `context` - Domain separation bytes (e.g., file_id, purpose)
    ///
    /// # Returns
    /// 32-byte derived key untuk AES-256.
    ///
    /// # Example
    /// ```rust,ignore
    /// let file_id = b"file_001";
    /// let key = wallet.derive_encryption_key(file_id);
    /// ```
    ///
    /// # Security Notes
    /// - Deterministik: same input → same output
    /// - Context WAJIB unique per file/purpose
    /// - Tidak panic
    pub fn derive_encryption_key(&self, context: &[u8]) -> [u8; 32] {
        use sha3::{Sha3_256, Digest};
        
        let mut hasher = Sha3_256::new();
        hasher.update(self.secret_key());
        hasher.update(context);
        
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result[..32]);
        key
    }
    
    /// Encrypt file dengan wallet-derived key.
    ///
    /// Menggunakan AES-256-GCM authenticated encryption.
    /// Nonce di-generate random untuk setiap enkripsi.
    ///
    /// # Arguments
    /// * `plaintext` - Data yang akan dienkripsi
    /// * `file_id` - Unique identifier untuk key derivation context
    ///
    /// # Returns
    /// * `Ok(EncryptedFile)` - Berisi nonce, ciphertext, dan tag
    /// * `Err(WalletError::EncryptionFailed)` - Jika encryption gagal
    ///
    /// # Example
    /// ```rust,ignore
    /// let plaintext = b"secret data";
    /// let file_id = b"file_001";
    /// let encrypted = wallet.encrypt_file(plaintext, file_id)?;
    /// ```
    ///
    /// # Security Notes
    /// - Nonce random 12 bytes untuk setiap enkripsi
    /// - Authentication tag 16 bytes (128-bit)
    /// - Key derived deterministik dari file_id
    pub fn encrypt_file(
        &self,
        plaintext: &[u8],
        file_id: &[u8],
    ) -> Result<EncryptedFile, WalletError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use rand::Rng;
        
        // Step 1: Derive key dengan file_id sebagai context
        let key = self.derive_encryption_key(file_id);
        
        // Step 2: Generate random nonce (12 bytes)
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Step 3: Create cipher dan encrypt
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| WalletError::EncryptionFailed)?;
        
        let ciphertext_with_tag = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| WalletError::EncryptionFailed)?;
        
        // Step 4: Separate ciphertext and tag
        // AES-GCM appends 16-byte tag to ciphertext
        if ciphertext_with_tag.len() < 16 {
            return Err(WalletError::EncryptionFailed);
        }
        
        let tag_start = ciphertext_with_tag.len() - 16;
        let ciphertext = ciphertext_with_tag[..tag_start].to_vec();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ciphertext_with_tag[tag_start..]);
        
        Ok(EncryptedFile::new(nonce_bytes, ciphertext, tag))
    }
    
    /// Decrypt file dengan wallet-derived key.
    ///
    /// Menggunakan AES-256-GCM authenticated decryption.
    /// Tag WAJIB valid untuk decryption berhasil.
    ///
    /// # Arguments
    /// * `encrypted` - EncryptedFile dari encrypt_file()
    /// * `file_id` - Identifier yang sama saat encrypt
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Decrypted plaintext
    /// * `Err(WalletError::AuthenticationFailed)` - Tag invalid
    /// * `Err(WalletError::DecryptionFailed)` - Decryption error
    ///
    /// # Example
    /// ```rust,ignore
    /// let plaintext = wallet.decrypt_file(&encrypted, file_id)?;
    /// ```
    ///
    /// # Security Notes
    /// - Authentication tag WAJIB match
    /// - Same file_id WAJIB digunakan
    /// - Tidak panic
    pub fn decrypt_file(
        &self,
        encrypted: &EncryptedFile,
        file_id: &[u8],
    ) -> Result<Vec<u8>, WalletError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        
        // Step 1: Derive key dengan context yang sama
        let key = self.derive_encryption_key(file_id);
        
        // Step 2: Reconstruct nonce
        let nonce = Nonce::from_slice(encrypted.nonce());
        
        // Step 3: Create cipher
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| WalletError::DecryptionFailed)?;
        
        // Step 4: Reconstruct ciphertext with tag for aes-gcm
        // aes-gcm expects ciphertext || tag
        let mut ciphertext_with_tag = encrypted.ciphertext().to_vec();
        ciphertext_with_tag.extend_from_slice(encrypted.tag());
        
        // Step 5: Decrypt dan verify tag
        let plaintext = cipher
            .decrypt(nonce, ciphertext_with_tag.as_slice())
            .map_err(|_| WalletError::AuthenticationFailed)?;
        
        Ok(plaintext)
    }
    
    /// Wrap file encryption key untuk sharing ke recipient.
    ///
    /// Menggunakan X25519 ECDH untuk derive shared secret,
    /// kemudian encrypt file_key dengan AES-256-GCM.
    ///
    /// # Arguments
    /// * `file_key` - 32-byte file encryption key
    /// * `recipient_pubkey` - Recipient's X25519 public key (32 bytes)
    ///
    /// # Returns
    /// Wrapped key bytes: ephemeral_pubkey (32) || encrypted_key (32) || tag (16) || nonce (12)
    /// Total: 92 bytes
    ///
    /// # Example
    /// ```rust,ignore
    /// let wrapped = wallet.wrap_file_key(&file_key, &recipient_pubkey);
    /// // Send wrapped bytes to recipient
    /// ```
    ///
    /// # Security Notes
    /// - Ephemeral keypair generated per wrap
    /// - Forward secrecy dari ephemeral key
    /// - Authenticated encryption untuk key
    pub fn wrap_file_key(
        &self,
        file_key: &[u8; 32],
        recipient_pubkey: &[u8; 32],
    ) -> Vec<u8> {
        use x25519_dalek::{StaticSecret, PublicKey};
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use sha3::{Sha3_256, Digest};
        use rand::Rng;
        
        // Step 1: Generate ephemeral X25519 keypair using random bytes
        let mut ephemeral_secret_bytes = [0u8; 32];
        rand::thread_rng().fill(&mut ephemeral_secret_bytes);
        let ephemeral_secret = StaticSecret::from(ephemeral_secret_bytes);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        
        // Step 2: Derive shared secret via ECDH
        let recipient_pk = PublicKey::from(*recipient_pubkey);
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pk);
        
        // Step 3: Derive encryption key dari shared secret
        let mut hasher = Sha3_256::new();
        hasher.update(b"dsdn_file_key_wrap_v1");
        hasher.update(shared_secret.as_bytes());
        let wrap_key: [u8; 32] = hasher.finalize().into();
        
        // Step 4: Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Step 5: Encrypt file_key dengan wrap_key
        let cipher = match Aes256Gcm::new_from_slice(&wrap_key) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let encrypted_key = match cipher.encrypt(nonce, file_key.as_slice()) {
            Ok(ct) => ct,
            Err(_) => return Vec::new(),
        };
        
        // Step 6: Construct wrapped output
        // Format: ephemeral_pubkey (32) || encrypted_key_with_tag (48) || nonce (12)
        let mut wrapped = Vec::with_capacity(92);
        wrapped.extend_from_slice(ephemeral_public.as_bytes());
        wrapped.extend_from_slice(&encrypted_key);
        wrapped.extend_from_slice(&nonce_bytes);
        
        wrapped
    }
    
    /// Unwrap file encryption key received dari sender.
    ///
    /// Decrypt wrapped key menggunakan wallet's secret key
    /// dan ephemeral public key dari sender.
    ///
    /// # Arguments
    /// * `wrapped_key` - 92-byte wrapped key dari wrap_file_key()
    ///
    /// # Returns
    /// * `Ok([u8; 32])` - Decrypted file key
    /// * `Err(WalletError::InvalidCiphertext)` - Invalid format
    /// * `Err(WalletError::AuthenticationFailed)` - Decryption failed
    ///
    /// # Example
    /// ```rust,ignore
    /// let file_key = wallet.unwrap_file_key(&wrapped)?;
    /// // Use file_key untuk decrypt file
    /// ```
    ///
    /// # Security Notes
    /// - Memerlukan wallet's secret key
    /// - Tag verification untuk integrity
    pub fn unwrap_file_key(
        &self,
        wrapped_key: &[u8],
    ) -> Result<[u8; 32], WalletError> {
        use x25519_dalek::{PublicKey, StaticSecret};
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use sha3::{Sha3_256, Digest};
        
        // Validate length: 32 (pubkey) + 48 (encrypted_key + tag) + 12 (nonce) = 92
        if wrapped_key.len() != 92 {
            return Err(WalletError::InvalidCiphertext);
        }
        
        // Step 1: Extract components
        let mut ephemeral_pubkey_bytes = [0u8; 32];
        ephemeral_pubkey_bytes.copy_from_slice(&wrapped_key[0..32]);
        let encrypted_key_with_tag = &wrapped_key[32..80];
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&wrapped_key[80..92]);
        
        // Step 2: Convert wallet secret to X25519 secret
        // Ed25519 secret key dapat digunakan untuk X25519 dengan hashing
        let mut hasher = Sha3_256::new();
        hasher.update(b"dsdn_ed25519_to_x25519");
        hasher.update(self.secret_key());
        let x25519_secret_bytes: [u8; 32] = hasher.finalize().into();
        let my_secret = StaticSecret::from(x25519_secret_bytes);
        
        // Step 3: Derive shared secret via ECDH
        let ephemeral_pubkey = PublicKey::from(ephemeral_pubkey_bytes);
        let shared_secret = my_secret.diffie_hellman(&ephemeral_pubkey);
        
        // Step 4: Derive wrap key
        let mut hasher = Sha3_256::new();
        hasher.update(b"dsdn_file_key_wrap_v1");
        hasher.update(shared_secret.as_bytes());
        let wrap_key: [u8; 32] = hasher.finalize().into();
        
        // Step 5: Decrypt file_key
        let cipher = Aes256Gcm::new_from_slice(&wrap_key)
            .map_err(|_| WalletError::DecryptionFailed)?;
        
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let file_key_bytes = cipher
            .decrypt(nonce, encrypted_key_with_tag)
            .map_err(|_| WalletError::AuthenticationFailed)?;
        
        // Step 6: Validate length
        if file_key_bytes.len() != 32 {
            return Err(WalletError::InvalidCiphertext);
        }
        
        let mut file_key = [0u8; 32];
        file_key.copy_from_slice(&file_key_bytes);
        
        Ok(file_key)
    }
    
    /// Get X25519 public key untuk key wrapping.
    ///
    /// Derived dari wallet's Ed25519 secret key.
    /// Recipient menggunakan ini untuk wrap_file_key().
    ///
    /// # Returns
    /// 32-byte X25519 public key.
    pub fn x25519_public_key(&self) -> [u8; 32] {
        use x25519_dalek::{PublicKey, StaticSecret};
        use sha3::{Sha3_256, Digest};
        
        // Convert Ed25519 secret to X25519
        let mut hasher = Sha3_256::new();
        hasher.update(b"dsdn_ed25519_to_x25519");
        hasher.update(self.secret_key());
        let x25519_secret_bytes: [u8; 32] = hasher.finalize().into();
        
        let secret = StaticSecret::from(x25519_secret_bytes);
        let public = PublicKey::from(&secret);
        
        *public.as_bytes()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// DA VERIFICATION METHODS (13.17.6)
// ════════════════════════════════════════════════════════════════════════════════
// Wallet convenience methods untuk Data Availability verification.
// Tidak menggunakan secret key - hanya helper wrapper.
// ════════════════════════════════════════════════════════════════════════════════

impl Wallet {
    /// Verify data matches DA blob commitment.
    ///
    /// Convenience wrapper untuk compute_blob_commitment.
    /// Tidak menggunakan wallet secret key.
    ///
    /// # Arguments
    /// * `data` - Blob data untuk diverifikasi
    /// * `commitment` - BlobCommitment untuk dibandingkan
    ///
    /// # Returns
    /// * `true` - Data matches commitment
    /// * `false` - Data does not match commitment
    ///
    /// # Example
    /// ```rust,ignore
    /// let data = b"blob content";
    /// let commitment = BlobCommitment { ... };
    /// if wallet.verify_da_commitment(data, &commitment) {
    ///     println!("Data verified!");
    /// }
    /// ```
    ///
    /// # Security Notes
    /// - TIDAK menggunakan secret key
    /// - Hanya wrapper untuk compute_blob_commitment
    /// - Tidak panic
    pub fn verify_da_commitment(
        &self,
        data: &[u8],
        commitment: &BlobCommitment,
    ) -> bool {
        use crate::celestia::compute_blob_commitment;
        
        let computed = compute_blob_commitment(data);
        computed == commitment.commitment
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// DISPLAY TRAITS (safe - only shows address, NEVER secret)
// ════════════════════════════════════════════════════════════════════════════════

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // HANYA show address dan public key, TIDAK PERNAH secret key
        f.debug_struct("Wallet")
            .field("address", &self.address)
            .field("public_key", &hex::encode(&self.public_key))
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════════════════
// UNIT TESTS (13.17.1)
// ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_wallet_generate() {
        let wallet = Wallet::generate();
        
        // Address tidak boleh zero
        assert_ne!(wallet.address(), Address::from_bytes([0u8; 20]));
        
        // Public key harus 32 bytes
        assert_eq!(wallet.public_key().len(), 32);
        
        // Secret key harus 32 bytes
        assert_eq!(wallet.secret_key().len(), 32);
        
        // Keypair harus 64 bytes
        assert_eq!(wallet.export_keypair().len(), 64);
        
        // Public key di struct harus sama dengan keypair[32..64]
        assert_eq!(wallet.public_key(), &wallet.export_keypair()[32..64]);
        
        // Secret key harus sama dengan keypair[0..32]
        assert_eq!(wallet.secret_key(), &wallet.export_keypair()[0..32]);
        
        println!("✅ test_wallet_generate PASSED");
    }
    
    #[test]
    fn test_wallet_from_secret_key() {
        // Generate wallet
        let original = Wallet::generate();
        let mut secret = [0u8; 32];
        secret.copy_from_slice(original.secret_key());
        
        // Restore dari secret
        let restored = Wallet::from_secret_key(&secret);
        
        // Address harus match
        assert_eq!(original.address(), restored.address());
        
        // Public key harus match
        assert_eq!(original.public_key(), restored.public_key());
        
        // Secret key harus match
        assert_eq!(original.secret_key(), restored.secret_key());
        
        println!("✅ test_wallet_from_secret_key PASSED");
    }
    
    #[test]
    fn test_wallet_from_bytes() {
        // Generate wallet
        let original = Wallet::generate();
        let keypair = original.export_keypair();
        
        // Restore dari bytes
        let restored = Wallet::from_bytes(&keypair);
        
        // Address harus match
        assert_eq!(original.address(), restored.address());
        
        // Public key harus match
        assert_eq!(original.public_key(), restored.public_key());
        
        // Secret key harus match
        assert_eq!(original.secret_key(), restored.secret_key());
        
        // Full keypair harus match
        assert_eq!(original.export_keypair(), restored.export_keypair());
        
        println!("✅ test_wallet_from_bytes PASSED");
    }
    
    #[test]
    fn test_wallet_export_secret_hex() {
        let wallet = Wallet::generate();
        let hex_str = wallet.export_secret_hex();
        
        // Harus 64 hex characters (32 bytes)
        assert_eq!(hex_str.len(), 64);
        
        // Harus valid hex
        assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));
        
        // Harus lowercase
        assert!(hex_str.chars().all(|c| !c.is_ascii_uppercase()));
        
        // Decode dan compare dengan secret_key
        let decoded = hex::decode(&hex_str);
        assert!(decoded.is_ok());
        assert_eq!(&decoded.unwrap()[..], wallet.secret_key());
        
        println!("✅ test_wallet_export_secret_hex PASSED");
    }
    
    #[test]
    fn test_wallet_determinism() {
        // Same secret harus selalu produce same wallet
        let secret = [0x42u8; 32];
        
        let wallet1 = Wallet::from_secret_key(&secret);
        let wallet2 = Wallet::from_secret_key(&secret);
        
        assert_eq!(wallet1.address(), wallet2.address());
        assert_eq!(wallet1.public_key(), wallet2.public_key());
        assert_eq!(wallet1.secret_key(), wallet2.secret_key());
        assert_eq!(wallet1.export_keypair(), wallet2.export_keypair());
        
        println!("✅ test_wallet_determinism PASSED");
    }
    
    #[test]
    fn test_wallet_debug_does_not_leak_secret() {
        let wallet = Wallet::generate();
        let debug_str = format!("{:?}", wallet);
        
        // Debug harus contain address
        assert!(debug_str.contains("address"));
        
        // Debug harus contain public_key
        assert!(debug_str.contains("public_key"));
        
        // Debug TIDAK BOLEH contain "secret" atau "keypair_bytes"
        let lowercase = debug_str.to_lowercase();
        assert!(!lowercase.contains("secret"));
        assert!(!lowercase.contains("keypair_bytes"));
        
        // Secret key hex TIDAK BOLEH muncul di debug string
        let secret_hex = wallet.export_secret_hex();
        assert!(!debug_str.contains(&secret_hex));
        
        println!("✅ test_wallet_debug_does_not_leak_secret PASSED");
    }
    
    #[test]
    fn test_wallet_different_secrets_different_addresses() {
        let wallet1 = Wallet::from_secret_key(&[0x01u8; 32]);
        let wallet2 = Wallet::from_secret_key(&[0x02u8; 32]);
        
        // Different secrets harus produce different addresses
        assert_ne!(wallet1.address(), wallet2.address());
        assert_ne!(wallet1.public_key(), wallet2.public_key());
        
        println!("✅ test_wallet_different_secrets_different_addresses PASSED");
    }
    
    #[test]
    fn test_wallet_keypair_structure() {
        let wallet = Wallet::generate();
        let keypair = wallet.export_keypair();
        
        // keypair[0..32] harus = secret_key
        assert_eq!(&keypair[0..32], wallet.secret_key());
        
        // keypair[32..64] harus = public_key
        assert_eq!(&keypair[32..64], wallet.public_key());
        
        println!("✅ test_wallet_keypair_structure PASSED");
    }
    
    // ════════════════════════════════════════════════════════════════════════════════
    // SIGNING TESTS (13.17.2)
    // ════════════════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_wallet_sign_message() {
        let wallet = Wallet::generate();
        let message = b"hello world";
        
        // Sign message
        let signature = wallet.sign_message(message);
        
        // Signature harus 64 bytes
        assert_eq!(signature.len(), 64, "Signature must be 64 bytes");
        
        // Signature tidak boleh semua zero
        assert!(!signature.iter().all(|&b| b == 0), "Signature should not be all zeros");
        
        println!("✅ test_wallet_sign_message PASSED");
    }
    
    #[test]
    fn test_wallet_verify_signature() {
        let wallet = Wallet::generate();
        let message = b"hello blockchain";
        
        // Sign message
        let signature = wallet.sign_message(message);
        
        // Verify signature
        assert!(wallet.verify_signature(message, &signature), "Signature should be valid");
        
        println!("✅ test_wallet_verify_signature PASSED");
    }
    
    #[test]
    fn test_wallet_verify_signature_wrong_message() {
        let wallet = Wallet::generate();
        let message1 = b"message one";
        let message2 = b"message two";
        
        // Sign message1
        let signature = wallet.sign_message(message1);
        
        // Verify dengan message2 harus fail
        assert!(!wallet.verify_signature(message2, &signature), 
            "Signature should be invalid for different message");
        
        println!("✅ test_wallet_verify_signature_wrong_message PASSED");
    }
    
    #[test]
    fn test_wallet_verify_signature_wrong_key() {
        let wallet1 = Wallet::generate();
        let wallet2 = Wallet::generate();
        let message = b"secret message";
        
        // Sign dengan wallet1
        let signature = wallet1.sign_message(message);
        
        // Verify dengan wallet2 harus fail
        assert!(!wallet2.verify_signature(message, &signature), 
            "Signature should be invalid for different wallet");
        
        println!("✅ test_wallet_verify_signature_wrong_key PASSED");
    }
    
    #[test]
    fn test_wallet_verify_signature_invalid_length() {
        let wallet = Wallet::generate();
        let message = b"test message";
        
        // Invalid signature lengths
        let short_sig = vec![0u8; 32];
        let long_sig = vec![0u8; 128];
        let empty_sig: Vec<u8> = vec![];
        
        assert!(!wallet.verify_signature(message, &short_sig), "Short signature should be invalid");
        assert!(!wallet.verify_signature(message, &long_sig), "Long signature should be invalid");
        assert!(!wallet.verify_signature(message, &empty_sig), "Empty signature should be invalid");
        
        println!("✅ test_wallet_verify_signature_invalid_length PASSED");
    }
    
    #[test]
    fn test_wallet_sign_determinism() {
        let wallet = Wallet::generate();
        let message = b"deterministic signing";
        
        // Sign same message twice
        let sig1 = wallet.sign_message(message);
        let sig2 = wallet.sign_message(message);
        
        // Signatures harus sama (Ed25519 deterministic)
        assert_eq!(sig1, sig2, "Ed25519 signatures should be deterministic");
        
        println!("✅ test_wallet_sign_determinism PASSED");
    }
    
    #[test]
    fn test_wallet_sign_empty_message() {
        let wallet = Wallet::generate();
        let empty_message: &[u8] = b"";
        
        // Sign empty message
        let signature = wallet.sign_message(empty_message);
        
        // Should still produce valid 64-byte signature
        assert_eq!(signature.len(), 64, "Empty message signature must be 64 bytes");
        
        // Should be verifiable
        assert!(wallet.verify_signature(empty_message, &signature), 
            "Empty message signature should be valid");
        
        println!("✅ test_wallet_sign_empty_message PASSED");
    }
    
    #[test]
    fn test_wallet_error_display() {
        let err1 = WalletError::SigningFailed("test error".to_string());
        let err2 = WalletError::InvalidKeyLength;
        let err3 = WalletError::SerializationError("serialize failed".to_string());
        
        // Check display output
        assert!(format!("{}", err1).contains("signing failed"));
        assert!(format!("{}", err2).contains("invalid key length"));
        assert!(format!("{}", err3).contains("serialization error"));
        
        println!("✅ test_wallet_error_display PASSED");
    }
    
    // ════════════════════════════════════════════════════════════════════════════════
    // ENCRYPTION TESTS (13.17.5)
    // ════════════════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_wallet_derive_encryption_key() {
        let wallet = Wallet::generate();
        
        // Derive key dengan context
        let context1 = b"file_001";
        let context2 = b"file_002";
        
        let key1a = wallet.derive_encryption_key(context1);
        let key1b = wallet.derive_encryption_key(context1);
        let key2 = wallet.derive_encryption_key(context2);
        
        // Key harus 32 bytes
        assert_eq!(key1a.len(), 32);
        
        // Same context → same key (deterministic)
        assert_eq!(key1a, key1b);
        
        // Different context → different key
        assert_ne!(key1a, key2);
        
        println!("✅ test_wallet_derive_encryption_key PASSED");
    }
    
    #[test]
    fn test_wallet_derive_encryption_key_different_wallets() {
        let wallet1 = Wallet::from_secret_key(&[0x01u8; 32]);
        let wallet2 = Wallet::from_secret_key(&[0x02u8; 32]);
        let context = b"same_context";
        
        let key1 = wallet1.derive_encryption_key(context);
        let key2 = wallet2.derive_encryption_key(context);
        
        // Different wallets → different keys
        assert_ne!(key1, key2);
        
        println!("✅ test_wallet_derive_encryption_key_different_wallets PASSED");
    }
    
    #[test]
    fn test_wallet_encrypt_decrypt_file() {
        let wallet = Wallet::generate();
        let plaintext = b"hello encrypted world";
        let file_id = b"test_file_001";
        
        // Encrypt
        let encrypted = wallet.encrypt_file(plaintext, file_id);
        assert!(encrypted.is_ok(), "Encryption should succeed");
        
        let encrypted = encrypted.unwrap();
        
        // Verify structure
        assert_eq!(encrypted.nonce().len(), 12);
        assert_eq!(encrypted.tag().len(), 16);
        assert_eq!(encrypted.ciphertext().len(), plaintext.len());
        
        // Decrypt
        let decrypted = wallet.decrypt_file(&encrypted, file_id);
        assert!(decrypted.is_ok(), "Decryption should succeed");
        
        assert_eq!(decrypted.unwrap(), plaintext);
        
        println!("✅ test_wallet_encrypt_decrypt_file PASSED");
    }
    
    #[test]
    fn test_wallet_encrypt_decrypt_empty() {
        let wallet = Wallet::generate();
        let plaintext: &[u8] = b"";
        let file_id = b"empty_file";
        
        // Encrypt empty
        let encrypted = wallet.encrypt_file(plaintext, file_id);
        assert!(encrypted.is_ok());
        
        let encrypted = encrypted.unwrap();
        assert_eq!(encrypted.ciphertext().len(), 0);
        
        // Decrypt empty
        let decrypted = wallet.decrypt_file(&encrypted, file_id);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintext);
        
        println!("✅ test_wallet_encrypt_decrypt_empty PASSED");
    }
    
    #[test]
    fn test_wallet_decrypt_wrong_file_id() {
        let wallet = Wallet::generate();
        let plaintext = b"secret data";
        let file_id = b"correct_id";
        let wrong_id = b"wrong_id";
        
        // Encrypt dengan correct_id
        let encrypted = wallet.encrypt_file(plaintext, file_id).unwrap();
        
        // Decrypt dengan wrong_id harus fail
        let result = wallet.decrypt_file(&encrypted, wrong_id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), WalletError::AuthenticationFailed);
        
        println!("✅ test_wallet_decrypt_wrong_file_id PASSED");
    }
    
    #[test]
    fn test_wallet_decrypt_tampered_ciphertext() {
        let wallet = Wallet::generate();
        let plaintext = b"important data";
        let file_id = b"file_id";
        
        // Encrypt
        let mut encrypted = wallet.encrypt_file(plaintext, file_id).unwrap();
        
        // Tamper ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }
        
        // Decrypt harus fail
        let result = wallet.decrypt_file(&encrypted, file_id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), WalletError::AuthenticationFailed);
        
        println!("✅ test_wallet_decrypt_tampered_ciphertext PASSED");
    }
    
    #[test]
    fn test_wallet_decrypt_tampered_tag() {
        let wallet = Wallet::generate();
        let plaintext = b"important data";
        let file_id = b"file_id";
        
        // Encrypt
        let mut encrypted = wallet.encrypt_file(plaintext, file_id).unwrap();
        
        // Tamper tag
        encrypted.tag[0] ^= 0xFF;
        
        // Decrypt harus fail
        let result = wallet.decrypt_file(&encrypted, file_id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), WalletError::AuthenticationFailed);
        
        println!("✅ test_wallet_decrypt_tampered_tag PASSED");
    }
    
    #[test]
    fn test_wallet_encryption_deterministic_key() {
        let secret = [0x42u8; 32];
        let wallet1 = Wallet::from_secret_key(&secret);
        let wallet2 = Wallet::from_secret_key(&secret);
        
        let plaintext = b"test message";
        let file_id = b"file_001";
        
        // Encrypt dengan wallet1
        let encrypted = wallet1.encrypt_file(plaintext, file_id).unwrap();
        
        // Decrypt dengan wallet2 (sama secret)
        let decrypted = wallet2.decrypt_file(&encrypted, file_id);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintext);
        
        println!("✅ test_wallet_encryption_deterministic_key PASSED");
    }
    
    #[test]
    fn test_wallet_x25519_public_key() {
        let wallet = Wallet::generate();
        let x25519_pk = wallet.x25519_public_key();
        
        // Harus 32 bytes
        assert_eq!(x25519_pk.len(), 32);
        
        // Harus deterministic
        let x25519_pk2 = wallet.x25519_public_key();
        assert_eq!(x25519_pk, x25519_pk2);
        
        // Harus berbeda dari Ed25519 public key
        assert_ne!(&x25519_pk[..], wallet.public_key());
        
        println!("✅ test_wallet_x25519_public_key PASSED");
    }
    
    #[test]
    fn test_wallet_wrap_unwrap_file_key() {
        let sender = Wallet::generate();
        let recipient = Wallet::generate();
        
        // File key untuk dienkripsi
        let file_key: [u8; 32] = [0x42u8; 32];
        
        // Sender wrap key untuk recipient
        let recipient_x25519_pk = recipient.x25519_public_key();
        let wrapped = sender.wrap_file_key(&file_key, &recipient_x25519_pk);
        
        // Wrapped harus 92 bytes
        assert_eq!(wrapped.len(), 92);
        
        // Recipient unwrap key
        let unwrapped = recipient.unwrap_file_key(&wrapped);
        assert!(unwrapped.is_ok(), "Unwrap should succeed");
        assert_eq!(unwrapped.unwrap(), file_key);
        
        println!("✅ test_wallet_wrap_unwrap_file_key PASSED");
    }
    
    #[test]
    fn test_wallet_unwrap_wrong_recipient() {
        let sender = Wallet::generate();
        let recipient = Wallet::generate();
        let wrong_recipient = Wallet::generate();
        
        let file_key: [u8; 32] = [0xABu8; 32];
        
        // Wrap untuk recipient
        let wrapped = sender.wrap_file_key(&file_key, &recipient.x25519_public_key());
        
        // Wrong recipient coba unwrap
        let result = wrong_recipient.unwrap_file_key(&wrapped);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), WalletError::AuthenticationFailed);
        
        println!("✅ test_wallet_unwrap_wrong_recipient PASSED");
    }
    
    #[test]
    fn test_wallet_unwrap_invalid_length() {
        let wallet = Wallet::generate();
        
        // Too short
        let short = vec![0u8; 50];
        let result = wallet.unwrap_file_key(&short);
        assert_eq!(result.unwrap_err(), WalletError::InvalidCiphertext);
        
        // Too long
        let long = vec![0u8; 100];
        let result = wallet.unwrap_file_key(&long);
        assert_eq!(result.unwrap_err(), WalletError::InvalidCiphertext);
        
        println!("✅ test_wallet_unwrap_invalid_length PASSED");
    }
    
    #[test]
    fn test_wallet_unwrap_tampered_wrapped_key() {
        let sender = Wallet::generate();
        let recipient = Wallet::generate();
        
        let file_key: [u8; 32] = [0xCDu8; 32];
        let mut wrapped = sender.wrap_file_key(&file_key, &recipient.x25519_public_key());
        
        // Tamper wrapped key
        wrapped[50] ^= 0xFF;
        
        let result = recipient.unwrap_file_key(&wrapped);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), WalletError::AuthenticationFailed);
        
        println!("✅ test_wallet_unwrap_tampered_wrapped_key PASSED");
    }
    
    #[test]
    fn test_wallet_encryption_error_display() {
        let err1 = WalletError::EncryptionFailed;
        let err2 = WalletError::DecryptionFailed;
        let err3 = WalletError::InvalidCiphertext;
        let err4 = WalletError::AuthenticationFailed;
        
        assert!(format!("{}", err1).contains("encryption"));
        assert!(format!("{}", err2).contains("decryption"));
        assert!(format!("{}", err3).contains("ciphertext"));
        assert!(format!("{}", err4).contains("authentication"));
        
        println!("✅ test_wallet_encryption_error_display PASSED");
    }
    
    // ════════════════════════════════════════════════════════════════════════════════
    // DA VERIFICATION TESTS (13.17.6)
    // ════════════════════════════════════════════════════════════════════════════════
    
    #[test]
    fn test_wallet_verify_da_commitment_true() {
        let wallet = Wallet::generate();
        let data = b"blob data for DA";
        
        // Compute correct commitment
        let commitment_bytes = crate::celestia::compute_blob_commitment(data);
        let commitment = BlobCommitment::new(
            commitment_bytes,
            [0u8; 29],
            100,
            0,
        );
        
        // Verify should return true
        assert!(wallet.verify_da_commitment(data, &commitment));
        
        println!("✅ test_wallet_verify_da_commitment_true PASSED");
    }
    
    #[test]
    fn test_wallet_verify_da_commitment_false() {
        let wallet = Wallet::generate();
        let data = b"original blob";
        let wrong_data = b"tampered blob";
        
        // Compute commitment from original
        let commitment_bytes = crate::celestia::compute_blob_commitment(data);
        let commitment = BlobCommitment::new(
            commitment_bytes,
            [0u8; 29],
            100,
            0,
        );
        
        // Verify with wrong data should return false
        assert!(!wallet.verify_da_commitment(wrong_data, &commitment));
        
        println!("✅ test_wallet_verify_da_commitment_false PASSED");
    }
    
    #[test]
    fn test_wallet_verify_da_commitment_no_secret_key_needed() {
        // Different wallets should verify the same (no secret key used)
        let wallet1 = Wallet::from_secret_key(&[0x01u8; 32]);
        let wallet2 = Wallet::from_secret_key(&[0x02u8; 32]);
        
        let data = b"shared verification";
        let commitment_bytes = crate::celestia::compute_blob_commitment(data);
        let commitment = BlobCommitment::new(
            commitment_bytes,
            [0u8; 29],
            100,
            0,
        );
        
        // Both wallets should verify the same
        assert_eq!(
            wallet1.verify_da_commitment(data, &commitment),
            wallet2.verify_da_commitment(data, &commitment)
        );
        
        println!("✅ test_wallet_verify_da_commitment_no_secret_key_needed PASSED");
    }
}