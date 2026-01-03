//! Crypto helpers: Ed25519 keypair generation, sign, verify, and hex utilities.
//! Compatible with ed25519-dalek v2.2.0 + rand_core feature enabled.
//!
//! Combined key format (64 bytes):
//!   [0..32]  = private key bytes
//!   [32..64] = public key bytes

use ed25519_dalek::{Signer, Verifier, Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use hex::{encode as hex_encode, decode as hex_decode};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid key length: expected {expected}, found {found}")]
    InvalidKeyLength { expected: usize, found: usize },

    #[error("verification failed")]
    VerifyFailed,

    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
}

/// Generate a new Ed25519 keypair and return concatenated 64-byte (private + public).
pub fn generate_keypair_bytes() -> Result<Vec<u8>, CryptoError> {
    let mut rng = OsRng;
    let sk = SigningKey::generate(&mut rng);
    let vk = sk.verifying_key();

    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(&sk.to_bytes());
    combined.extend_from_slice(&vk.to_bytes());
    Ok(combined)
}

/// Build a SigningKey from combined keypair bytes.
pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, CryptoError> {
    if bytes.len() != 64 {
        return Err(CryptoError::InvalidKeyLength { expected: 64, found: bytes.len() });
    }
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&bytes[0..32]);
    Ok(SigningKey::from_bytes(&sk_bytes))
}

/// Extract public key bytes from 64-byte keypair.
pub fn public_key_bytes_from_keypair_bytes(kp_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if kp_bytes.len() != 64 {
        return Err(CryptoError::InvalidKeyLength { expected: 64, found: kp_bytes.len() });
    }
    Ok(kp_bytes[32..64].to_vec())
}

/// Sign a message and return 64-byte signature.
pub fn sign_message(kp_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let sk = signing_key_from_bytes(kp_bytes)?;
    let sig = sk.sign(message);
    Ok(sig.to_bytes().to_vec())
}

/// Verify a message given public key and signature.
pub fn verify_signature(pubkey_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<bool, CryptoError> {
    if pubkey_bytes.len() != 32 {
        return Err(CryptoError::InvalidKeyLength { expected: 32, found: pubkey_bytes.len() });
    }
    if sig_bytes.len() != 64 {
        return Err(CryptoError::InvalidKeyLength { expected: 64, found: sig_bytes.len() });
    }

    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(pubkey_bytes);
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| CryptoError::VerifyFailed)?;

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);

    match vk.verify(message, &sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Hex helpers
pub fn keypair_bytes_to_hex(kp_bytes: &[u8]) -> String {
    hex_encode(kp_bytes)
}

pub fn keypair_bytes_from_hex(hexstr: &str) -> Result<Vec<u8>, CryptoError> {
    Ok(hex_decode(hexstr)?)
}

pub fn public_key_bytes_to_hex(pk: &[u8]) -> String {
    hex_encode(pk)
}

pub fn public_key_bytes_from_hex(hexstr: &str) -> Result<Vec<u8>, CryptoError> {
    Ok(hex_decode(hexstr)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        let kp_bytes = generate_keypair_bytes().expect("generate kp");
        let pub_bytes = public_key_bytes_from_keypair_bytes(&kp_bytes).expect("pub bytes");
        let msg = b"hello dsdn";
        let sig = sign_message(&kp_bytes, msg).expect("sign");
        let ok = verify_signature(&pub_bytes, msg, &sig).expect("verify");
        assert!(ok, "signature should verify");

        // tamper message
        let ok2 = verify_signature(&pub_bytes, b"hello dsdn!", &sig).expect("verify");
        assert!(!ok2, "tampered message should fail verify");
    }

    #[test]
    fn test_hex_serialization() {
        let kp_bytes = generate_keypair_bytes().expect("generate kp");
        let hex = keypair_bytes_to_hex(&kp_bytes);
        let back = keypair_bytes_from_hex(&hex).expect("from hex");
        assert_eq!(kp_bytes, back);
    }
}
