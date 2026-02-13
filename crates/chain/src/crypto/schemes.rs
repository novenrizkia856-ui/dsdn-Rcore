use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CryptoSchemeId {
    Ed25519 = 1,
    Dilithium = 2,
}

impl TryFrom<u8> for CryptoSchemeId {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Ed25519),
            2 => Ok(Self::Dilithium),
            _ => Err(anyhow!("unsupported crypto scheme id: {}", value)),
        }
    }
}

pub trait SignatureScheme {
    const SCHEME_ID: CryptoSchemeId;

    fn generate_keypair_bytes() -> Result<(Vec<u8>, Vec<u8>)>;
    fn public_key_from_secret(secret: &[u8]) -> Result<Vec<u8>>;
    fn sign_with_secret_key(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>>;
    fn sign_with_keypair_bytes(keypair_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>>;
    fn verify_signature(pubkey_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<bool>;
}
