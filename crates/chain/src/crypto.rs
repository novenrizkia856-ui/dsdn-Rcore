//! crypto helpers for dsdn-chain: hashing + pluggable signature schemes
use anyhow::{anyhow, Result};
use hex::encode as hex_encode;
use sha3::{Digest, Sha3_512};

use crate::types::{Address, Hash};

#[path = "crypto/dilithium_backend.rs"]
mod dilithium_backend;
#[path = "crypto/ed25519_backend.rs"]
mod ed25519_backend;
#[path = "crypto/schemes.rs"]
mod schemes;

pub use ed25519_backend::Ed25519PrivateKey;
pub use schemes::{CryptoSchemeId, SignatureScheme};

use dilithium_backend::DilithiumBackend;
use ed25519_backend::Ed25519Backend;

const SIGNATURE_FORMAT_V1: u8 = 1;
const DEFAULT_SCHEME: CryptoSchemeId = CryptoSchemeId::Ed25519;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSignature {
    pub scheme: CryptoSchemeId,
    pub signature: Vec<u8>,
    pub is_legacy: bool,
}

pub fn encode_signature(scheme: CryptoSchemeId, signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + signature.len());
    out.push(SIGNATURE_FORMAT_V1);
    out.push(scheme as u8);
    out.extend_from_slice(signature);
    out
}

pub fn decode_signature(signature: &[u8]) -> Result<DecodedSignature> {
    if signature.len() >= 2 && signature[0] == SIGNATURE_FORMAT_V1 {
        let scheme = CryptoSchemeId::try_from(signature[1])?;
        return Ok(DecodedSignature {
            scheme,
            signature: signature[2..].to_vec(),
            is_legacy: false,
        });
    }

    Ok(DecodedSignature {
        scheme: DEFAULT_SCHEME,
        signature: signature.to_vec(),
        is_legacy: true,
    })
}

/// compute sha3-512 hex string of bytes
pub fn sha3_512_hex(data: &[u8]) -> String {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    let sum = hasher.finalize();
    hex_encode(sum)
}

/// compute sha3-512 raw bytes (64 bytes)
pub fn sha3_512_bytes(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    let sum = hasher.finalize();
    sum.into()
}

/// compute sha3-512 and return as Hash type
pub fn sha3_512(data: &[u8]) -> Hash {
    Hash::from_bytes(sha3_512_bytes(data))
}

fn dispatch_verify(
    scheme: CryptoSchemeId,
    pubkey_bytes: &[u8],
    msg: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    match scheme {
        CryptoSchemeId::Ed25519 => Ed25519Backend::verify_signature(pubkey_bytes, msg, sig_bytes),
        CryptoSchemeId::Dilithium => {
            DilithiumBackend::verify_signature(pubkey_bytes, msg, sig_bytes)
        }
    }
}

/// Default keypair generation using active default scheme.
pub fn generate_ed25519_keypair_bytes() -> (Vec<u8>, Vec<u8>) {
    Ed25519Backend::generate_keypair_bytes().expect("ed25519 generation must be available")
}

pub fn public_key_from_secret_key(secret: &[u8]) -> Result<Vec<u8>> {
    Ed25519Backend::public_key_from_secret(secret)
}

/// Sign message with secret key bytes; returns encoded signature bytes (scheme-aware format).
pub fn sign_with_secret_key(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let raw = Ed25519Backend::sign_with_secret_key(secret, msg)?;
    Ok(encode_signature(CryptoSchemeId::Ed25519, &raw))
}

/// Sign message with keypair bytes; returns encoded signature bytes (scheme-aware format).
pub fn sign_message_with_keypair_bytes(keypair_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let raw = Ed25519Backend::sign_with_keypair_bytes(keypair_bytes, msg)?;
    Ok(encode_signature(CryptoSchemeId::Ed25519, &raw))
}

/// Verify signature given public key bytes, message, and signature bytes.
/// Accepts both legacy signatures (raw bytes) and scheme-aware format v1.
pub fn verify_signature(pubkey_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<bool> {
    let decoded = decode_signature(sig_bytes)?;
    dispatch_verify(decoded.scheme, pubkey_bytes, msg, &decoded.signature)
}

pub fn ed25519_verify(pubkey_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> bool {
    verify_signature(pubkey_bytes, msg, sig_bytes).unwrap_or(false)
}

pub fn sign_ed25519(pk: &Ed25519PrivateKey, msg: &[u8]) -> Result<Vec<u8>> {
    sign_with_secret_key(pk.as_bytes(), msg)
}

/// Derive Address from raw public key bytes: addr = SHA3-512(pubkey)[:20]
pub fn address_from_pubkey_bytes(pubkey_bytes: &[u8]) -> Result<Address> {
    let hash = sha3_512_bytes(pubkey_bytes);
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&hash[0..20]);
    Ok(Address::from_bytes(arr))
}

pub fn decode_signature_required_scheme(
    sig_bytes: &[u8],
    required: CryptoSchemeId,
) -> Result<Vec<u8>> {
    let decoded = decode_signature(sig_bytes)?;
    if decoded.scheme != required {
        return Err(anyhow!(
            "signature scheme mismatch: expected {:?}, got {:?}",
            required,
            decoded.scheme
        ));
    }
    Ok(decoded.signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha3_test() {
        let h = sha3_512_hex(b"hello");
        assert!(!h.is_empty());
        assert_eq!(h, sha3_512_hex(b"hello"));
    }

    #[test]
    fn signature_format_supports_legacy_and_v1() {
        let (pk, kp_bytes) = generate_ed25519_keypair_bytes();
        let msg = b"hello dsdn";
        let sig_v1 = sign_message_with_keypair_bytes(&kp_bytes, msg).expect("sign");
        assert!(verify_signature(&pk, msg, &sig_v1).expect("verify v1"));

        let decoded = decode_signature(&sig_v1).expect("decode");
        assert_eq!(decoded.scheme, CryptoSchemeId::Ed25519);
        assert!(!decoded.is_legacy);

        assert!(verify_signature(&pk, msg, &decoded.signature).expect("verify legacy"));
    }

    #[test]
    fn address_len_derived() {
        let (pk, _kp_bytes) = generate_ed25519_keypair_bytes();
        let addr = address_from_pubkey_bytes(&pk).expect("addr");
        assert_eq!(addr.to_hex().len(), 40);
        assert_eq!(addr.as_bytes().len(), 20);
    }
}
