

















































use crate::types::Address;
use crate::crypto::{generate_ed25519_keypair_bytes, address_from_pubkey_bytes, sign_message_with_keypair_bytes, verify_signature};
use crate::tx::TxEnvelope;
use crate::encryption::EncryptedFile;
use crate::celestia::BlobCommitment;
use crate::mnemonic::{self, MnemonicError};












#[derive(Debug, Clone, PartialEq)]
pub enum WalletError {

SigningFailed(String),


InvalidKeyLength,


SerializationError(String),






EncryptionFailed,


DecryptionFailed,


InvalidCiphertext,



AuthenticationFailed,


MnemonicError(String),
}

impl std::fmt::Display for WalletError {
fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
match self {
WalletError::SigningFailed(msg) => { write!(f, "signing failed: {}", msg) },
WalletError::InvalidKeyLength => { write!(f, "invalid key length") },
WalletError::SerializationError(msg) => { write!(f, "serialization error: {}", msg) },
WalletError::EncryptionFailed => { write!(f, "encryption failed") },
WalletError::DecryptionFailed => { write!(f, "decryption failed") },
WalletError::InvalidCiphertext => { write!(f, "invalid ciphertext") },
WalletError::AuthenticationFailed => { write!(f, "authentication failed") },
WalletError::MnemonicError(msg) => { write!(f, "mnemonic error: {}", msg) },
}
}
}

impl std::error::Error for WalletError {}

impl From<MnemonicError> for WalletError {
fn from(e: MnemonicError) -> Self {
WalletError::MnemonicError(e.to_string())
}
}

















pub struct Wallet {


keypair_bytes: [u8; 64],



public_key: [u8; 32],



address: Address,
}





impl Wallet {


















pub fn generate() -> Self {


let (pubkey_vec, keypair_vec) = generate_ed25519_keypair_bytes();


assert_eq!(keypair_vec.len(), 64, "invalid keypair length");

let mut keypair_bytes = [0u8; 64];
keypair_bytes.copy_from_slice(&keypair_vec);



let mut public_key = [0u8; 32];
public_key.copy_from_slice(&keypair_bytes[32..64]);



let address = match address_from_pubkey_bytes(&pubkey_vec) {
Ok(addr) => { addr },
Err(_) => { Address::from_bytes([0u8; 20]) },
};

Self {
keypair_bytes: keypair_bytes,
public_key: public_key,
address: address,
}
}























pub fn from_secret_key(secret: &[u8; 32]) -> Self {
let public_key_bytes = crate::crypto::ecdsa::public_key_from_secret(secret);


let mut keypair_bytes = [0u8; 64];
keypair_bytes[0..32].copy_from_slice(secret);
keypair_bytes[32..64].copy_from_slice(&public_key_bytes);


let address = match address_from_pubkey_bytes(&public_key_bytes.to_vec()) {
Ok(addr) => { addr },
Err(_) => { Address::from_bytes([0u8; 20]) },
};

Self {
keypair_bytes: keypair_bytes,
public_key: public_key_bytes,
address: address,
}
}























pub fn from_bytes(keypair_bytes: &[u8; 64]) -> Self {

let mut public_key = [0u8; 32];
public_key.copy_from_slice(&keypair_bytes[32..64]);


let address = match address_from_pubkey_bytes(&public_key.to_vec()) {
Ok(addr) => { addr },
Err(_) => { Address::from_bytes([0u8; 20]) },
};

Self {
keypair_bytes: *keypair_bytes,
public_key: public_key,
address: address,
}
}






















pub fn generate_with_mnemonic() -> (Self, String) {
let (phrase, secret) = mnemonic::generate_mnemonic()
.expect("BIP39 mnemonic generation should not fail");

let wallet = Self::from_secret_key(&secret);
(wallet, phrase)
}


















pub fn from_mnemonic(phrase: &str) -> Result<Self, WalletError> {
let secret = mnemonic::mnemonic_to_secret_key(phrase)?;
Ok(Self::from_secret_key(&secret))
}
}





impl Wallet {









#[inline]
pub fn address(&self) -> Address {
self.address
}










#[inline]
pub fn public_key(&self) -> &[u8; 32] {
&self.public_key
}











#[inline]
pub fn secret_key(&self) -> &[u8; 32] {











<&[u8; 32]>::try_from(&self.keypair_bytes[0..32])
.expect("keypair_bytes always 64 bytes")
}





impl Wallet {










#[inline]
pub fn export_keypair(&self) -> [u8; 64] {
self.keypair_bytes
}

















pub fn export_secret_hex(&self) -> String {
hex::encode(&self.keypair_bytes[0..32])
}


















pub fn export_mnemonic(&self) -> Result<String, WalletError> {
let secret: &[u8; 32] = <&[u8; 32]>::try_from(&self.keypair_bytes[0..32])
.expect("keypair_bytes always 64 bytes");


mnemonic::secret_key_to_mnemonic(secret).map_err(|e| e.into())
}
}

















impl Wallet {























pub fn sign_message(&self, message: &[u8]) -> Vec<u8> {


match sign_message_with_keypair_bytes(&self.keypair_bytes, message) {
Ok(signature) => { signature },
Err(_) => { Vec::new() },
}
}

























pub fn sign_tx(&self, mut tx: &TxEnvelope) -> Result<TxEnvelope, WalletError> {

let payload_bytes = tx.payload_bytes()
.map_err(|e| WalletError::SerializationError(format!("{}", e)))?;


let signature = sign_message_with_keypair_bytes(&self.keypair_bytes, &payload_bytes)
.map_err(|e| WalletError::SigningFailed(format!("{}", e)))?;


if signature.len() != 64 {
return Err(WalletError::SigningFailed(
format!("invalid signature length: {} (expected 64)", signature.len())
))
}


let mut signed_tx = tx.clone();
signed_tx.signature = signature;
signed_tx.pubkey = self.public_key.to_vec();

Ok(signed_tx)
}























pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
verify_signature(&self.public_key, &message, &signature).unwrap_or(false)
}
}




















impl Wallet {





















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

























pub fn encrypt_file(&self, plaintext: &[u8], file_id: &[u8]) -> Result<EncryptedFile, WalletError> {
use aes_gcm::{
aead::{Aead, KeyInit},
Aes256Gcm, Nonce,
};
use rand::Rng;


let key = self.derive_encryption_key(file_id);


let mut nonce_bytes = [0u8; 12];
rand::thread_rng().fill(&mut nonce_bytes);
let nonce = Nonce::from_slice(&nonce_bytes);


let cipher = Aes256Gcm::new_from_slice(&key)
.map_err(|_| WalletError::EncryptionFailed)?;

let ciphertext_with_tag = cipher
.encrypt(nonce, plaintext)
.map_err(|_| WalletError::EncryptionFailed)?;



if ciphertext_with_tag.len() < 16 {
return Err(WalletError::EncryptionFailed);
}

let tag_start = ciphertext_with_tag.len() - 16;
let ciphertext = ciphertext_with_tag[..tag_start].to_vec();
let mut tag = [0u8; 16];
tag.copy_from_slice(&ciphertext_with_tag[tag_start..]);

Ok(EncryptedFile::new(nonce_bytes, ciphertext, tag))
}
























pub fn decrypt_file(&self, encrypted: &EncryptedFile, file_id: &[u8]) -> Result<Vec<u8>, WalletError> {
use aes_gcm::{
aead::{Aead, KeyInit},
Aes256Gcm, Nonce,
};


let key = self.derive_encryption_key(file_id);


let nonce = Nonce::from_slice(encrypted.nonce());


let cipher = Aes256Gcm::new_from_slice(&key)
.map_err(|_| WalletError::DecryptionFailed)?;



let mut ciphertext_with_tag = encrypted.ciphertext().to_vec();
ciphertext_with_tag.extend_from_slice(encrypted.tag());


let plaintext = cipher
.decrypt(nonce, ciphertext_with_tag.as_slice())
.map_err(|_| WalletError::AuthenticationFailed)?;

Ok(plaintext)
}
























pub fn wrap_file_key(&self, file_key: &[u8; 32], recipient_pubkey: &[u8; 32]) -> Vec<u8> {
use x25519_dalek::{StaticSecret, PublicKey};
use aes_gcm::{
aead::{Aead, KeyInit},
Aes256Gcm, Nonce,
};
use sha3::{Sha3_256, Digest};
use rand::Rng;


let mut ephemeral_secret_bytes = [0u8; 32];
rand::thread_rng().fill(&mut ephemeral_secret_bytes);
let ephemeral_secret = StaticSecret::from(ephemeral_secret_bytes.clone());
let ephemeral_public = PublicKey::from(&ephemeral_secret);


let recipient_pk = PublicKey::from(*recipient_pubkey);
let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pk);


let mut hasher = Sha3_256::new();
hasher.update(b"dsdn_file_key_wrap_v1");
hasher.update(shared_secret.as_bytes());
let wrap_key: [u8; 32] = hasher.finalize().into();


let mut nonce_bytes = [0u8; 12];
rand::thread_rng().fill(&mut nonce_bytes);
let nonce = Nonce::from_slice(&nonce_bytes);


let cipher = match Aes256Gcm::new_from_slice(&wrap_key) {
Ok(c) => { c },
Err(_) => { return Vec::new() },
};

let encrypted_key = match cipher.encrypt(nonce, file_key.as_slice()) {
Ok(ct) => { ct },
Err(_) => { return Vec::new() },
};



let mut wrapped = Vec::with_capacity(92);
wrapped.extend_from_slice(ephemeral_public.as_bytes());
wrapped.extend_from_slice(&encrypted_key);
wrapped.extend_from_slice(&nonce_bytes);

wrapped
}























pub fn unwrap_file_key(&self, wrapped_key: &[u8]) -> Result<[u8; 32], WalletError> {
use x25519_dalek::{PublicKey, StaticSecret};
use aes_gcm::{
aead::{Aead, KeyInit},
Aes256Gcm, Nonce,
};
use sha3::{Sha3_256, Digest};


if wrapped_key.len() != 92 {
return Err(WalletError::InvalidCiphertext);
}


let mut ephemeral_pubkey_bytes = [0u8; 32];
ephemeral_pubkey_bytes.copy_from_slice(&wrapped_key[0..32]);
let encrypted_key_with_tag = &wrapped_key[32..80];
let mut nonce_bytes = [0u8; 12];
nonce_bytes.copy_from_slice(&wrapped_key[80..92]);



let mut hasher = Sha3_256::new();
hasher.update(b"dsdn_ed25519_to_x25519");
hasher.update(self.secret_key());
let x25519_secret_bytes: [u8; 32] = hasher.finalize().into();
let my_secret = StaticSecret::from(x25519_secret_bytes.clone());


let ephemeral_pubkey = PublicKey::from(ephemeral_pubkey_bytes.clone());
let shared_secret = my_secret.diffie_hellman(&ephemeral_pubkey);


let mut hasher = Sha3_256::new();
hasher.update(b"dsdn_file_key_wrap_v1");
hasher.update(shared_secret.as_bytes());
let wrap_key: [u8; 32] = hasher.finalize().into();


let cipher = Aes256Gcm::new_from_slice(&wrap_key)
.map_err(|_| WalletError::DecryptionFailed)?;

let nonce = Nonce::from_slice(&nonce_bytes);

let file_key_bytes = cipher
.decrypt(nonce, encrypted_key_with_tag)
.map_err(|_| WalletError::AuthenticationFailed)?;


if file_key_bytes.len() != 32 {
return Err(WalletError::InvalidCiphertext);
}

let mut file_key = [0u8; 32];
file_key.copy_from_slice(&file_key_bytes);

Ok(file_key)
}








pub fn x25519_public_key(&self) -> [u8; 32] {
use x25519_dalek::{PublicKey, StaticSecret};
use sha3::{Sha3_256, Digest};


let mut hasher = Sha3_256::new();
hasher.update(b"dsdn_ed25519_to_x25519");
hasher.update(self.secret_key());
let x25519_secret_bytes: [u8; 32] = hasher.finalize().into();

let secret = StaticSecret::from(x25519_secret_bytes.clone());
let public = PublicKey::from(&secret);

*public.as_bytes()
}
}








impl Wallet {


























pub fn verify_da_commitment(&self, data: &[u8], commitment: &BlobCommitment) -> bool {
use crate::celestia::compute_blob_commitment;

let computed = compute_blob_commitment(data);
computed == commitment.commitment
}
}





impl std::fmt::Debug for Wallet {
fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {

f.debug_struct("Wallet")
.field("address", &self.address)
.field("public_key", &hex::encode(&self.public_key))
.finish()
}
}





#[cfg(test)]
mod tests {
use super::*;

#[test]
fn test_wallet_generate() {
let wallet = Wallet::generate();


assert_ne!(wallet.address(), Address::from_bytes([0u8; 20]));


assert_eq!(wallet.public_key().len(), 32);


assert_eq!(wallet.secret_key().len(), 32);


assert_eq!(wallet.export_keypair().len(), 64);


assert_eq!(wallet.public_key(), &wallet.export_keypair()[32..64]);


assert_eq!(wallet.secret_key(), &wallet.export_keypair()[0..32]);

println!("✅ test_wallet_generate PASSED");
}

#[test]
fn test_wallet_from_secret_key() {

let original = Wallet::generate();
let mut secret = [0u8; 32];
secret.copy_from_slice(original.secret_key());


let restored = Wallet::from_secret_key(&secret);


assert_eq!(original.address(), restored.address());


assert_eq!(original.public_key(), restored.public_key());


assert_eq!(original.secret_key(), restored.secret_key());

println!("✅ test_wallet_from_secret_key PASSED");
}

#[test]
fn test_wallet_from_bytes() {

let original = Wallet::generate();
let keypair = original.export_keypair();


let restored = Wallet::from_bytes(&keypair);


assert_eq!(original.address(), restored.address());


assert_eq!(original.public_key(), restored.public_key());


assert_eq!(original.secret_key(), restored.secret_key());


assert_eq!(original.export_keypair(), restored.export_keypair());

println!("✅ test_wallet_from_bytes PASSED");
}

#[test]
fn test_wallet_export_secret_hex() {
let wallet = Wallet::generate();
let hex_str = wallet.export_secret_hex();


assert_eq!(hex_str.len(), 64);


assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));


assert!(hex_str.chars().all(|c| !c.is_ascii_uppercase()));


let decoded = hex::decode(&hex_str);
assert!(decoded.is_ok());
assert_eq!(&decoded.unwrap()[..], wallet.secret_key());

println!("✅ test_wallet_export_secret_hex PASSED");
}

#[test]
fn test_wallet_determinism() {

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


assert!(debug_str.contains("address"));


assert!(debug_str.contains("public_key"));


let lowercase = debug_str.to_lowercase();
assert!(!lowercase.contains("secret"));
assert!(!lowercase.contains("keypair_bytes"));


let secret_hex = wallet.export_secret_hex();
assert!(!debug_str.contains(&secret_hex));

println!("✅ test_wallet_debug_does_not_leak_secret PASSED");
}

#[test]
fn test_wallet_different_secrets_different_addresses() {
let wallet1 = Wallet::from_secret_key(&[0x01u8; 32]);
let wallet2 = Wallet::from_secret_key(&[0x02u8; 32]);


assert_ne!(wallet1.address(), wallet2.address());
assert_ne!(wallet1.public_key(), wallet2.public_key());

println!("✅ test_wallet_different_secrets_different_addresses PASSED");
}

#[test]
fn test_wallet_keypair_structure() {
let wallet = Wallet::generate();
let keypair = wallet.export_keypair();


assert_eq!(&keypair[0..32], wallet.secret_key());


assert_eq!(&keypair[32..64], wallet.public_key());

println!("✅ test_wallet_keypair_structure PASSED");
}





#[test]
fn test_wallet_sign_message() {
let wallet = Wallet::generate();
let message = b"hello world";


let signature = wallet.sign_message(message);


assert_eq!(signature.len(), 64, "Signature must be 64 bytes");


assert!(!signature.iter().all(|&b| b == 0), "Signature should not be all zeros");

println!("✅ test_wallet_sign_message PASSED");
}

#[test]
fn test_wallet_verify_signature() {
let wallet = Wallet::generate();
let message = b"hello blockchain";


let signature = wallet.sign_message(message);


assert!(wallet.verify_signature(message, &signature), "Signature should be valid");

println!("✅ test_wallet_verify_signature PASSED");
}

#[test]
fn test_wallet_verify_signature_wrong_message() {
let wallet = Wallet::generate();
let message1 = b"message one";
let message2 = b"message two";


let signature = wallet.sign_message(message1);


assert!(!wallet.verify_signature(message2, &signature),
"Signature should be invalid for different message");

println!("✅ test_wallet_verify_signature_wrong_message PASSED");
}

#[test]
fn test_wallet_verify_signature_wrong_key() {
let wallet1 = Wallet::generate();
let wallet2 = Wallet::generate();
let message = b"secret message";


let signature = wallet1.sign_message(message);


assert!(!wallet2.verify_signature(message, &signature),
"Signature should be invalid for different wallet");

println!("✅ test_wallet_verify_signature_wrong_key PASSED");
}

#[test]
fn test_wallet_verify_signature_invalid_length() {
let wallet = Wallet::generate();
let message = b"test message";


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


let sig1 = wallet.sign_message(message);
let sig2 = wallet.sign_message(message);


assert_eq!(sig1, sig2, "Ed25519 signatures should be deterministic");

println!("✅ test_wallet_sign_determinism PASSED");
}

#[test]
fn test_wallet_sign_empty_message() {
let wallet = Wallet::generate();
let empty_message: &[u8] = b"";


let signature = wallet.sign_message(empty_message);


assert_eq!(signature.len(), 64, "Empty message signature must be 64 bytes");


assert!(wallet.verify_signature(empty_message, &signature),
"Empty message signature should be valid");

println!("✅ test_wallet_sign_empty_message PASSED");
}

#[test]
fn test_wallet_error_display() {
let err1 = WalletError::SigningFailed("test error".to_string());
let err2 = WalletError::InvalidKeyLength;
let err3 = WalletError::SerializationError("serialize failed".to_string());


assert!(format!("{}", err1).contains("signing failed"));
assert!(format!("{}", err2).contains("invalid key length"));
assert!(format!("{}", err3).contains("serialization error"));

println!("✅ test_wallet_error_display PASSED");
}





#[test]
fn test_wallet_derive_encryption_key() {
let wallet = Wallet::generate();


let context1 = b"file_001";
let context2 = b"file_002";

let key1a = wallet.derive_encryption_key(context1);
let key1b = wallet.derive_encryption_key(context1);
let key2 = wallet.derive_encryption_key(context2);


assert_eq!(key1a.len(), 32);


assert_eq!(key1a, key1b);


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


assert_ne!(key1, key2);

println!("✅ test_wallet_derive_encryption_key_different_wallets PASSED");
}

#[test]
fn test_wallet_encrypt_decrypt_file() {
let wallet = Wallet::generate();
let plaintext = b"hello encrypted world";
let file_id = b"test_file_001";


let mut encrypted = wallet.encrypt_file(plaintext, &file_id);
assert!(encrypted.is_ok(), "Encryption should succeed");

let encrypted = encrypted.unwrap();


assert_eq!(encrypted.nonce().len(), 12);
assert_eq!(encrypted.tag().len(), 16);
assert_eq!(encrypted.ciphertext().len(), plaintext.len());


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


let mut encrypted = wallet.encrypt_file(plaintext, &file_id);
assert!(encrypted.is_ok());

let encrypted = encrypted.unwrap();
assert_eq!(encrypted.ciphertext().len(), 0);


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


let encrypted = wallet.encrypt_file(plaintext, &file_id).unwrap();


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


let mut encrypted = wallet.encrypt_file(plaintext, &file_id).unwrap();


if !encrypted.ciphertext.is_empty() {
encrypted.ciphertext[0] ^= 0xFF;
}


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


let mut encrypted = wallet.encrypt_file(plaintext, &file_id).unwrap();


encrypted.tag[0] ^= 0xFF;


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


let encrypted = wallet1.encrypt_file(plaintext, &file_id).unwrap();


let decrypted = wallet2.decrypt_file(&encrypted, file_id);
assert!(decrypted.is_ok());
assert_eq!(decrypted.unwrap(), plaintext);

println!("✅ test_wallet_encryption_deterministic_key PASSED");
}

#[test]
fn test_wallet_x25519_public_key() {
let wallet = Wallet::generate();
let x25519_pk = wallet.x25519_public_key();


assert_eq!(x25519_pk.len(), 32);


let x25519_pk2 = wallet.x25519_public_key();
assert_eq!(x25519_pk, x25519_pk2);


assert_ne!(&x25519_pk[..], wallet.public_key());

println!("✅ test_wallet_x25519_public_key PASSED");
}

#[test]
fn test_wallet_wrap_unwrap_file_key() {
let sender = Wallet::generate();
let recipient = Wallet::generate();


let file_key: [u8; 32] = [0x42u8; 32];


let recipient_x25519_pk = recipient.x25519_public_key();
let wrapped = sender.wrap_file_key(&file_key, &recipient_x25519_pk);


assert_eq!(wrapped.len(), 92);


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


let wrapped = sender.wrap_file_key(&file_key, &recipient.x25519_public_key());


let result = wrong_recipient.unwrap_file_key(&wrapped);
assert!(result.is_err());
assert_eq!(result.unwrap_err(), WalletError::AuthenticationFailed);

println!("✅ test_wallet_unwrap_wrong_recipient PASSED");
}

#[test]
fn test_wallet_unwrap_invalid_length() {
let wallet = Wallet::generate();


let short = vec![0u8; 50];
let mut result = wallet.unwrap_file_key(&short);
assert_eq!(result.unwrap_err(), WalletError::InvalidCiphertext);


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





#[test]
fn test_wallet_generate_with_mnemonic() {
let (wallet, phrase) = Wallet::generate_with_mnemonic();


let words: Vec<&str> = phrase.split_whitespace().collect();
assert_eq!(words.len(), 24, "Must be 24 words");


assert_ne!(wallet.address(), Address::from_bytes([0u8; 20]));


assert_eq!(wallet.public_key().len(), 32);

println!("✅ test_wallet_generate_with_mnemonic PASSED");
}

#[test]
fn test_wallet_from_mnemonic_roundtrip() {
let (original, phrase) = Wallet::generate_with_mnemonic();


let restored = Wallet::from_mnemonic(&phrase).expect("import should succeed");


assert_eq!(original.address(), restored.address());


assert_eq!(original.public_key(), restored.public_key());


assert_eq!(original.secret_key(), restored.secret_key());

println!("✅ test_wallet_from_mnemonic_roundtrip PASSED");
}

#[test]
fn test_wallet_export_mnemonic() {
let (wallet, original_phrase) = Wallet::generate_with_mnemonic();


let exported_phrase = wallet.export_mnemonic().expect("export should succeed");


assert_eq!(original_phrase, exported_phrase);


let restored = Wallet::from_mnemonic(&exported_phrase).expect("import");
assert_eq!(wallet.address(), restored.address());
assert_eq!(wallet.secret_key(), restored.secret_key());

println!("✅ test_wallet_export_mnemonic PASSED");
}

#[test]
fn test_wallet_mnemonic_determinism() {
let (wallet1, phrase1) = Wallet::generate_with_mnemonic();


let wallet2 = Wallet::from_mnemonic(&phrase1).expect("import 1");
let wallet3 = Wallet::from_mnemonic(&phrase1).expect("import 2");

assert_eq!(wallet1.address(), wallet2.address());
assert_eq!(wallet2.address(), wallet3.address());
assert_eq!(wallet1.secret_key(), wallet2.secret_key());
assert_eq!(wallet2.secret_key(), wallet3.secret_key());

println!("✅ test_wallet_mnemonic_determinism PASSED");
}

#[test]
fn test_wallet_mnemonic_compatible_with_secret_key() {

let (mnemonic_wallet, phrase) = Wallet::generate_with_mnemonic();


let mut secret = [0u8; 32];
secret.copy_from_slice(mnemonic_wallet.secret_key());
let secret_wallet = Wallet::from_secret_key(&secret);


assert_eq!(mnemonic_wallet.address(), secret_wallet.address());
assert_eq!(mnemonic_wallet.public_key(), secret_wallet.public_key());


let exported = secret_wallet.export_mnemonic().expect("export");
assert_eq!(phrase, exported);

println!("✅ test_wallet_mnemonic_compatible_with_secret_key PASSED");
}

#[test]
fn test_wallet_from_mnemonic_invalid() {

let mut result = Wallet::from_mnemonic("abandon ability able");
assert!(result.is_err());


let result = Wallet::from_mnemonic("xyzzy foobar baz qux a b c d e f g h i j k l m n o p q r s t");
assert!(result.is_err());


let result = Wallet::from_mnemonic("");
assert!(result.is_err());

println!("✅ test_wallet_from_mnemonic_invalid PASSED");
}

#[test]
fn test_wallet_mnemonic_sign_verify() {

let (wallet, _phrase) = Wallet::generate_with_mnemonic();
let message = b"test signing from mnemonic wallet";

let signature = wallet.sign_message(message);
assert_eq!(signature.len(), 64);

assert!(wallet.verify_signature(message, &signature));

println!("✅ test_wallet_mnemonic_sign_verify PASSED");
}

#[test]
fn test_wallet_mnemonic_encrypt_decrypt() {

let (wallet, _phrase) = Wallet::generate_with_mnemonic();
let plaintext = b"encrypted with mnemonic wallet";
let file_id = b"mnemonic_file_001";

let encrypted = wallet.encrypt_file(plaintext, &file_id).expect("encrypt");
let decrypted = wallet.decrypt_file(&encrypted, file_id).expect("decrypt");

assert_eq!(decrypted, plaintext);

println!("✅ test_wallet_mnemonic_encrypt_decrypt PASSED");
}





#[test]
fn test_wallet_verify_da_commitment_true() {
let wallet = Wallet::generate();
let data = b"blob data for DA";


let commitment_bytes = crate::celestia::compute_blob_commitment(data);
let commitment = BlobCommitment::new(
commitment_bytes,
[0u8; 29],
100,
0,
);


assert!(wallet.verify_da_commitment(data, &commitment));

println!("✅ test_wallet_verify_da_commitment_true PASSED");
}

#[test]
fn test_wallet_verify_da_commitment_false() {
let wallet = Wallet::generate();
let data = b"original blob";
let wrong_data = b"tampered blob";


let commitment_bytes = crate::celestia::compute_blob_commitment(data);
let commitment = BlobCommitment::new(
commitment_bytes,
[0u8; 29],
100,
0,
);


assert!(!wallet.verify_da_commitment(wrong_data, &commitment));

println!("✅ test_wallet_verify_da_commitment_false PASSED");
}

#[test]
fn test_wallet_verify_da_commitment_no_secret_key_needed() {

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


assert_eq!(
wallet1.verify_da_commitment(data, &commitment),
wallet2.verify_da_commitment(data, &commitment)
);

println!("✅ test_wallet_verify_da_commitment_no_secret_key_needed PASSED");
}
}