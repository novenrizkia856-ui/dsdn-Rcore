//! crypto helpers for dsdn-chain: sha3-512, pluggable signature schemes, address derivation
use sha3::{Digest, Sha3_512};
use hex::encode as hex_encode;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use crate::types::{Address, Hash};
use ed25519_dalek::PublicKey as EcdsaPublicKey;

pub mod ecdsa;
pub mod dilithium;

/// Supported signature algorithms for on-chain payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoAlgorithm {
    Ecdsa,
    Dilithium,
}

impl Default for CryptoAlgorithm {
    fn default() -> Self {
        Self::Ecdsa
    }
}

/// Serialized signature with explicit algorithm identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorithmSignature {
    pub algorithm: CryptoAlgorithm,
    pub signature: Vec<u8>,
}

/// Serialized public key with explicit algorithm identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorithmPublicKey {
    pub algorithm: CryptoAlgorithm,
    pub public_key: Vec<u8>,
}

pub trait CryptoScheme {
    type PublicKey;
    type PrivateKey;
    type Signature;

    fn generate_keypair() -> (Self::PublicKey, Self::PrivateKey);
    fn sign(private: &Self::PrivateKey, message: &[u8]) -> Self::Signature;
    fn verify(public: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> bool;
}

pub struct CryptoEngine<A: CryptoScheme> {
    marker: std::marker::PhantomData<A>,
}

impl<A: CryptoScheme> CryptoEngine<A> {
    pub fn generate_keypair() -> (A::PublicKey, A::PrivateKey) {
        A::generate_keypair()
    }

    pub fn sign(private: &A::PrivateKey, message: &[u8]) -> A::Signature {
        A::sign(private, message)
    }

    pub fn verify(public: &A::PublicKey, message: &[u8], signature: &A::Signature) -> bool {
        A::verify(public, message, signature)
    }
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
    let bytes = sha3_512_bytes(data);
    Hash::from_bytes(bytes)
}

/// Default key generation. Kept for backward compatibility.
pub fn generate_ed25519_keypair_bytes() -> (Vec<u8>, Vec<u8>) {
    CryptoEngine::<ecdsa::EcdsaImpl>::generate_keypair()
}

/// Default signing API. Kept for backward compatibility.
pub fn sign_message_with_keypair_bytes(keypair_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    ecdsa::sign_message_with_keypair_bytes(keypair_bytes, msg)
}

/// Default signing API from 32-byte secret key.
pub fn sign_with_secret_key(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    ecdsa::sign_with_secret_key(secret, msg)
}

/// Verify signature using explicit algorithm.
pub fn verify_signature_with_algorithm(
    algorithm: CryptoAlgorithm,
    pubkey_bytes: &[u8],
    msg: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    match algorithm {
        CryptoAlgorithm::Ecdsa => ecdsa::verify_signature(pubkey_bytes, msg, sig_bytes),
        CryptoAlgorithm::Dilithium => Ok(dilithium::verify_signature(pubkey_bytes, msg, sig_bytes)),
    }
}

/// Default signature verification (Ecdsa) for compatibility.
pub fn verify_signature(pubkey_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<bool> {
    verify_signature_with_algorithm(CryptoAlgorithm::Ecdsa, pubkey_bytes, msg, sig_bytes)
}

/// Legacy helper name retained.
pub fn ed25519_verify(pubkey_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> bool {
    verify_signature(pubkey_bytes, msg, sig_bytes).unwrap_or(false)
}

/// Backward-compatible key wrapper for callers that store 32-byte private key material.
#[derive(Clone)]
pub struct Ed25519PrivateKey {
    raw: [u8; 32],
}

impl Ed25519PrivateKey {
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 32 {
            return Err(anyhow::anyhow!("private key must be 32 bytes"));
        }
        let mut raw = [0u8; 32];
        raw.copy_from_slice(b);
        Ok(Self { raw })
    }

    pub fn public_key(&self) -> EcdsaPublicKey {
        ecdsa::public_key_from_secret_key(&self.raw).expect("private key was validated at construction")
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    pub fn generate() -> Self {
        let (_pub, keypair) = generate_ed25519_keypair_bytes();
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&keypair[..32]);
        Self { raw }
    }
}

pub fn sign_ed25519(pk: &Ed25519PrivateKey, msg: &[u8]) -> Result<Vec<u8>> {
    sign_with_secret_key(pk.as_bytes(), msg)
}

/// Derive Address from raw public key bytes: addr = SHA3-512(pubkey)[:20]
pub fn address_from_pubkey_bytes(pubkey_bytes: &[u8]) -> Result<Address> {
    let hash = sha3_512_bytes(pubkey_bytes);
    let mut arr = [0u8;20];
    arr.copy_from_slice(&hash[0..20]);
    Ok(Address::from_bytes(arr))
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
    fn ecdsa_default_sign_verify() {
        let (pk, kp_bytes) = generate_ed25519_keypair_bytes();
        let msg = b"hello dsdn";
        let sig = sign_message_with_keypair_bytes(&kp_bytes, msg).expect("sign");
        let ok = verify_signature(&pk, msg, &sig).expect("verify");
        assert!(ok, "signature must verify");
    }

    #[test]
    fn address_len_derived() {
        let (pk, _kp_bytes) = generate_ed25519_keypair_bytes();
        let addr = address_from_pubkey_bytes(&pk).expect("addr");
        assert_eq!(addr.to_hex().len(), 40);
        assert_eq!(addr.as_bytes().len(), 20);
    }
}
