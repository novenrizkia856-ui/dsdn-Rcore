use anyhow::{anyhow, Result};

use super::schemes::{CryptoSchemeId, SignatureScheme};

pub struct DilithiumBackend;

impl SignatureScheme for DilithiumBackend {
    const SCHEME_ID: CryptoSchemeId = CryptoSchemeId::Dilithium;

    fn generate_keypair_bytes() -> Result<(Vec<u8>, Vec<u8>)> {
        Err(anyhow!("dilithium backend is not implemented yet"))
    }

    fn public_key_from_secret(_secret: &[u8]) -> Result<Vec<u8>> {
        Err(anyhow!("dilithium backend is not implemented yet"))
    }

    fn sign_with_secret_key(_secret: &[u8], _msg: &[u8]) -> Result<Vec<u8>> {
        Err(anyhow!("dilithium backend is not implemented yet"))
    }

    fn sign_with_keypair_bytes(_keypair_bytes: &[u8], _msg: &[u8]) -> Result<Vec<u8>> {
        Err(anyhow!("dilithium backend is not implemented yet"))
    }

    fn verify_signature(_pubkey_bytes: &[u8], _msg: &[u8], _sig_bytes: &[u8]) -> Result<bool> {
        Err(anyhow!("dilithium backend is not implemented yet"))
    }
}
