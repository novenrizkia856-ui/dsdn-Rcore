use anyhow::Result;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand_core::OsRng;

use super::CryptoScheme;

pub struct EcdsaImpl;

impl CryptoScheme for EcdsaImpl {
    type PublicKey = Vec<u8>;
    type PrivateKey = Vec<u8>;
    type Signature = Vec<u8>;

    fn generate_keypair() -> (Self::PublicKey, Self::PrivateKey) {
        let mut csprng = OsRng {};
        let kp: Keypair = Keypair::generate(&mut csprng);
        (kp.public.to_bytes().to_vec(), kp.to_bytes().to_vec())
    }

    fn sign(private: &Self::PrivateKey, message: &[u8]) -> Self::Signature {
        sign_message_with_keypair_bytes(private, message).unwrap_or_default()
    }

    fn verify(public: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> bool {
        verify_signature(public, message, signature).unwrap_or(false)
    }
}

pub fn sign_with_secret_key(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let secret_key = SecretKey::from_bytes(secret)
        .map_err(|e| anyhow::anyhow!("invalid secret key: {}", e))?;
    let public_key: PublicKey = (&secret_key).into();
    let kp = Keypair { secret: secret_key, public: public_key };
    let sig: Signature = kp.sign(msg);
    Ok(sig.to_bytes().to_vec())
}

pub fn sign_message_with_keypair_bytes(keypair_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let kp = Keypair::from_bytes(keypair_bytes)
        .map_err(|e| anyhow::anyhow!("invalid keypair bytes: {}", e))?;
    let sig: Signature = kp.sign(msg);
    Ok(sig.to_bytes().to_vec())
}

pub fn verify_signature(pubkey_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<bool> {
    let pk = PublicKey::from_bytes(pubkey_bytes)
        .map_err(|e| anyhow::anyhow!("invalid public key: {}", e))?;
    let sig = Signature::from_bytes(sig_bytes)
        .map_err(|e| anyhow::anyhow!("invalid signature: {}", e))?;
    Ok(pk.verify(msg, &sig).is_ok())
}


pub fn public_key_from_secret_key(secret: &[u8; 32]) -> Option<PublicKey> {
    let sk = SecretKey::from_bytes(secret).ok()?;
    Some(PublicKey::from(&sk))
}

pub fn public_key_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    let sk = match SecretKey::from_bytes(secret) {
        Ok(sk) => sk,
        Err(_) => return [0u8; 32],
    };
    PublicKey::from(&sk).to_bytes()
}
