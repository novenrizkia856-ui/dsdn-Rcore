//! Crypto helpers for dsdn-chain: hashing, signature abstraction, and address derivation.
use sha3::{Digest, Sha3_512};
use hex::encode as hex_encode;
use ed25519_dalek::{Keypair, Signature, Signer, Verifier, PublicKey, SecretKey};
use rand_core::OsRng;
use anyhow::Result;
use crate::types::{Address, Hash};

/// Signature scheme variants supported by the chain crypto layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureAlgorithm {
    Ed25519,
}

/// Generic signature algorithm interface.
pub trait SignatureScheme {
    fn algorithm(&self) -> SignatureAlgorithm;
    fn generate_keypair_bytes(&self) -> Result<(Vec<u8>, Vec<u8>)>;
    fn sign_with_keypair_bytes(&self, keypair_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, pubkey_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<bool>;
}

/// Ed25519 implementation of [`SignatureScheme`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Ed25519Scheme;

impl SignatureScheme for Ed25519Scheme {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }

    fn generate_keypair_bytes(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut csprng = OsRng{};
        let kp: Keypair = Keypair::generate(&mut csprng);
        let pk_bytes = kp.public.to_bytes().to_vec();
        let kp_bytes = kp.to_bytes().to_vec(); // 64 bytes
        Ok((pk_bytes, kp_bytes))
    }

    fn sign_with_keypair_bytes(&self, keypair_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        let kp = Keypair::from_bytes(keypair_bytes)
            .map_err(|e| anyhow::anyhow!("invalid keypair bytes: {}", e))?;
        let sig: Signature = kp.sign(msg);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(&self, pubkey_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<bool> {
        let pk = PublicKey::from_bytes(pubkey_bytes)
            .map_err(|e| anyhow::anyhow!("invalid public key: {}", e))?;
        let sig = Signature::from_bytes(sig_bytes)
            .map_err(|e| anyhow::anyhow!("invalid signature: {}", e))?;
        match pk.verify(msg, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

pub fn default_signature_scheme() -> Ed25519Scheme {
    Ed25519Scheme
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

/// Generate Ed25519 keypair and return (public_bytes, keypair_bytes).
/// - public_bytes: 32 bytes
/// - keypair_bytes: 64 bytes (secret(32) || public(32))
pub fn generate_ed25519_keypair_bytes() -> (Vec<u8>, Vec<u8>) {
    default_signature_scheme()
        .generate_keypair_bytes()
        .expect("ed25519 keypair generation should not fail")
}

/// Sign message with secret key bytes (32 bytes). Derives public key internally. Returns signature bytes (64).
pub fn sign_with_secret_key(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let secret_key = SecretKey::from_bytes(secret)
        .map_err(|e| anyhow::anyhow!("invalid secret key: {}", e))?;
    let public_key: PublicKey = (&secret_key).into();
    let kp = Keypair { secret: secret_key, public: public_key };
    let sig: Signature = kp.sign(msg);
    Ok(sig.to_bytes().to_vec())
}

/// Sign message with keypair bytes (64 bytes). Returns signature bytes (64).
pub fn sign_message_with_keypair_bytes(keypair_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    default_signature_scheme().sign_with_keypair_bytes(keypair_bytes, msg)
}

/// Verify signature given public key bytes (32), message and signature bytes (64)
pub fn verify_signature(pubkey_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<bool> {
    default_signature_scheme().verify(pubkey_bytes, msg, sig_bytes)
}

/// Verify Ed25519 signature (returns bool, no Result).
/// Returns false for any invalid input (pubkey length, signature length, verification failure).
pub fn ed25519_verify(pubkey_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> bool {
    if pubkey_bytes.len() != 32 || sig_bytes.len() != 64 {
        return false;
    }
    let pk = match PublicKey::from_bytes(pubkey_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = match Signature::from_bytes(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    pk.verify(msg, &sig).is_ok()
}
/// Ed25519 private key wrapper that stores raw 32 bytes (secret)
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

    pub fn to_secret(&self) -> Result<SecretKey> {
        SecretKey::from_bytes(&self.raw)
            .map_err(|e| anyhow::anyhow!("invalid secret key: {}", e))
    }

    pub fn public_key(&self) -> PublicKey {
        let sk = SecretKey::from_bytes(&self.raw).unwrap();
        PublicKey::from(&sk)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Generate random private key (ed25519-dalek style)
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let secret = ed25519_dalek::SecretKey::generate(&mut rng);
        let mut raw = [0u8; 32];
        raw.copy_from_slice(secret.as_bytes());
        Self { raw }
    }
}

pub fn sign_ed25519(pk: &Ed25519PrivateKey, msg: &[u8]) -> Result<Vec<u8>> {
    let sk = pk.to_secret()?;
    let pk2 = PublicKey::from(&sk);
    let kp = Keypair { secret: sk, public: pk2 };
    let sig = kp.sign(msg);
    Ok(sig.to_bytes().to_vec())
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
    fn ed25519_sign_verify() {
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

    #[test]
    fn signature_scheme_abstraction_roundtrip() {
        let scheme = default_signature_scheme();
        assert_eq!(scheme.algorithm(), SignatureAlgorithm::Ed25519);

        let (pk, kp) = scheme.generate_keypair_bytes().expect("generate");
        let msg = b"abstraction-layer";
        let sig = scheme.sign_with_keypair_bytes(&kp, msg).expect("sign");
        let ok = scheme.verify(&pk, msg, &sig).expect("verify");
        assert!(ok, "signature scheme abstraction should verify");
    }
}
