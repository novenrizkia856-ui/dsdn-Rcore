use anyhow::{anyhow, Result};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand_core::OsRng;

use super::schemes::{CryptoSchemeId, SignatureScheme};

pub struct Ed25519Backend;

impl SignatureScheme for Ed25519Backend {
    const SCHEME_ID: CryptoSchemeId = CryptoSchemeId::Ed25519;

    fn generate_keypair_bytes() -> Result<(Vec<u8>, Vec<u8>)> {
        let mut csprng = OsRng {};
        let kp = Keypair::generate(&mut csprng);
        Ok((kp.public.to_bytes().to_vec(), kp.to_bytes().to_vec()))
    }

    fn public_key_from_secret(secret: &[u8]) -> Result<Vec<u8>> {
        let secret_key =
            SecretKey::from_bytes(secret).map_err(|e| anyhow!("invalid secret key: {}", e))?;
        let public_key: PublicKey = (&secret_key).into();
        Ok(public_key.to_bytes().to_vec())
    }

    fn sign_with_secret_key(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        let secret_key =
            SecretKey::from_bytes(secret).map_err(|e| anyhow!("invalid secret key: {}", e))?;
        let public_key: PublicKey = (&secret_key).into();
        let kp = Keypair {
            secret: secret_key,
            public: public_key,
        };
        Ok(kp.sign(msg).to_bytes().to_vec())
    }

    fn sign_with_keypair_bytes(keypair_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        let kp = Keypair::from_bytes(keypair_bytes)
            .map_err(|e| anyhow!("invalid keypair bytes: {}", e))?;
        Ok(kp.sign(msg).to_bytes().to_vec())
    }

    fn verify_signature(pubkey_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<bool> {
        let pk = PublicKey::from_bytes(pubkey_bytes)
            .map_err(|e| anyhow!("invalid public key: {}", e))?;
        let sig =
            Signature::from_bytes(sig_bytes).map_err(|e| anyhow!("invalid signature: {}", e))?;
        Ok(pk.verify(msg, &sig).is_ok())
    }
}

#[derive(Clone)]
pub struct Ed25519PrivateKey {
    raw: [u8; 32],
}

impl Ed25519PrivateKey {
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 32 {
            return Err(anyhow!("private key must be 32 bytes"));
        }
        let mut raw = [0u8; 32];
        raw.copy_from_slice(b);
        Ok(Self { raw })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    pub fn generate() -> Self {
        let mut rng = OsRng;
        let secret = SecretKey::generate(&mut rng);
        let mut raw = [0u8; 32];
        raw.copy_from_slice(secret.as_bytes());
        Self { raw }
    }
}
