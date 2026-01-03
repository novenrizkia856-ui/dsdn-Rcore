//! Block structure
use serde::{Serialize, Deserialize};
use crate::crypto::sha3_512_bytes;
use crate::types::{Hash, Address};
use chrono::{Utc, DateTime};
use crate::tx::TxEnvelope;
use anyhow::{Result, anyhow};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockHeader {
    pub parent_hash: Hash,
    pub state_root: Hash,
    pub tx_root: Hash,
    pub height: u64,
    pub timestamp: DateTime<Utc>,
    pub proposer: Address,
    pub proposer_pubkey: Vec<u8>, // Public key for signature verification (13.7.J)
    pub signature: Vec<u8>,
    pub gas_used: u64,
    pub gas_limit: u64,
    /// Round number dalam konsensus (untuk BFT/Tendermint-style)
    #[serde(default)]
    pub round_number: u64,
    /// Index proposer dari Proposer Selection Engine
    #[serde(default)]
    pub proposer_index: u32,
    /// VRF seed untuk verifiable randomness (future use)
    #[serde(default)]
    pub vrf_seed: Option<[u8; 32]>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub body: BlockBody,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockBody {
    pub transactions: Vec<TxEnvelope>,
    pub receipts: Vec<Receipt>, // now mandatory
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Receipt {
    pub tx_hash: Hash,
    pub success: bool,
    pub gas_used: u64,
    pub events: Vec<String>,
}

impl Block {
    /// Compute tx_root: Merkle root of transaction hashes (SHA3-512 of concatenated txids)
    pub fn compute_tx_root(txs: &[TxEnvelope]) -> Hash {
        if txs.is_empty() {
            return Hash::from_bytes(sha3_512_bytes(b""));
        }

        let mut accum = Vec::new();
        for tx in txs {
            match tx.compute_txid() {
                Ok(h) => accum.extend_from_slice(h.as_bytes()),
                Err(_) => {
                    if let Ok(b) = tx.payload_bytes() {
                        accum.extend_from_slice(&sha3_512_bytes(&b));
                    }
                }
            }
        }
        Hash::from_bytes(sha3_512_bytes(&accum))
    }

    pub fn compute_hash(header: &BlockHeader) -> Hash {
        let header_bytes = serde_json::to_vec(&(
            &header.parent_hash,
            &header.state_root,
            &header.tx_root,
            &header.height,
            &header.timestamp,
            &header.proposer,
            &header.gas_used,
            &header.gas_limit,
            // Consensus metadata (13.7.M)
            &header.round_number,
            &header.proposer_index,
            &header.vrf_seed,
        )).unwrap_or_default();
        Hash::from_bytes(sha3_512_bytes(&header_bytes))
    }
   pub fn new(
        height: u64,
        parent_hash: Hash,
        txs: Vec<TxEnvelope>,
        state_root: Hash,
        proposer: Address,
        proposer_pubkey: Vec<u8>,
        gas_used: u64,
        gas_limit: u64,
    ) -> Self {
        let tx_root = Self::compute_tx_root(&txs);
        let ts = Utc::now();

        let header = BlockHeader {
            parent_hash,
            state_root,
            tx_root,
            height,
            timestamp: ts,
            proposer,
            proposer_pubkey,
            signature: vec![0u8; 64],
            gas_used,
            gas_limit,
            // Consensus metadata defaults (13.7.M)
            round_number: 0,
            proposer_index: 0,
            vrf_seed: None,
        };

        Block {
            header,
            body: BlockBody {
                transactions: txs,
                receipts: Vec::new(), // set later
            },
        }
    }

    /// Create block with full consensus metadata (13.7.M)
    pub fn new_with_consensus(
        height: u64,
        parent_hash: Hash,
        txs: Vec<TxEnvelope>,
        state_root: Hash,
        proposer: Address,
        proposer_pubkey: Vec<u8>,
        gas_used: u64,
        gas_limit: u64,
        round_number: u64,
        proposer_index: u32,
        vrf_seed: Option<[u8; 32]>,
    ) -> Self {
        let tx_root = Self::compute_tx_root(&txs);
        let ts = Utc::now();

        let header = BlockHeader {
            parent_hash,
            state_root,
            tx_root,
            height,
            timestamp: ts,
            proposer,
            proposer_pubkey,
            signature: vec![0u8; 64],
            gas_used,
            gas_limit,
            round_number,
            proposer_index,
            vrf_seed,
        };

        Block {
            header,
            body: BlockBody {
                transactions: txs,
                receipts: Vec::new(),
            },
        }
    }

    /// Sign the header with proposer's secret key (32 bytes)
    pub fn sign(&mut self, secret_key: &[u8]) -> Result<()> {
        let hash = Self::compute_hash(&self.header);
        let signature = crate::crypto::sign_with_secret_key(secret_key, hash.as_bytes())?;
        self.header.signature = signature;
        Ok(())
    }

    /// Verify block signature given proposer's public key bytes (32 bytes)
    pub fn verify_signature(&self) -> Result<bool> {
        if self.header.proposer_pubkey.is_empty() {
            return Err(anyhow!("proposer_pubkey is empty, cannot verify"));
        }
        let hash = Self::compute_hash(&self.header);
        crate::crypto::verify_signature(
            &self.header.proposer_pubkey, 
            hash.as_bytes(), 
            &self.header.signature
        )
    }

    /// Verify block signature with explicit public key (legacy support)
    pub fn verify_signature_with_pubkey(&self, pubkey_bytes: &[u8]) -> Result<bool> {
        let hash = Self::compute_hash(&self.header);
        crate::crypto::verify_signature(pubkey_bytes, hash.as_bytes(), &self.header.signature)
    }
}