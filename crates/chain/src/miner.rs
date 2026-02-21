// crates/chain/src/miner.rs
//! Simple miner / block producer (PoS mode with signing)
//! NONCE-SAFE VERSION (sorted pending tx by nonce)
//! 
//! 13.8.E Fee Distribution:
//! - Transfer:   Validator (proposer) receives 100%
//! - Governance: Validator 50%, Treasury 50%
//! - Storage:    Storage Node 100% (proposer gets NOTHING)
//! - Compute:    Compute Node 100% (proposer gets NOTHING)
use crate::block::{Block, Receipt};
use crate::tx::{TxEnvelope, TxPayload};
use crate::state::ChainState;
use crate::types::{Hash, Address};
use anyhow::{Result, anyhow};

/// Optional: uncomment these if you want derive public key from private key
/// and add ed25519-dalek to Cargo.toml:
/// ed25519-dalek = "1.0.1"
///
/// use ed25519_dalek::{SecretKey, PublicKey};

pub struct Miner {
    proposer: Address,
    private_key: Vec<u8>,  // Ed25519 secret key (32 bytes)
    public_key: Vec<u8>,   // Ed25519 public key (32 bytes)
}

impl Miner {
    /// Backward-compatible constructor (2-arg).
    /// This keeps existing call sites (Miner::new(proposer, priv)) working.
    /// Uses a zeroed public_key as placeholder for full nodes / dev mode.
    pub fn new(proposer: Address, private_key: Vec<u8>) -> Self {
        Miner {
            proposer,
            private_key,
            // placeholder public key (full nodes / dev mode)
            public_key: vec![0u8; 32],
        }
    }

    /// Explicit constructor accepting both private & public keys.
    /// Use this when you actually have the public key (validator/proposer).
    pub fn with_keys(proposer: Address, private_key: Vec<u8>, public_key: Vec<u8>) -> Self {
        Miner { proposer, private_key, public_key }
    }

    /// Alternative constructor: derive public key from private key (requires ed25519-dalek)
    /// Returns Result<Self> because key derivation can fail.
    /// To enable this, add `ed25519-dalek = "1.0.1"` to Cargo.toml.
    #[allow(dead_code)]
    pub fn from_private(proposer: Address, private_key: Vec<u8>) -> Result<Self> {
        // If you don't want to use ed25519-dalek, remove this function.
        // Make sure to add `ed25519-dalek = "1.0.1"` to Cargo.toml if using.
        if private_key.len() != 32 {
            return Err(anyhow!("private key must be 32 bytes (seed) to derive public key"));
        }

        let mut secret_arr = [0u8; 32];
        secret_arr.copy_from_slice(&private_key);
        let public = crate::crypto::ecdsa::public_key_from_secret(&secret_arr);
        Ok(Miner {
            proposer,
            private_key,
            public_key: public.to_vec(),
        })
    }

    pub fn mine_block(
        &self,
        txs: Vec<TxEnvelope>,
        state: &mut ChainState,
        parent_hash: Hash,
        height: u64,
    ) -> Result<Block> {
        println!("═══════════════════════════════════════════════════════════");
        println!("🔨 BLOCK PRODUCTION CYCLE START - Height: {}", height);
        println!("   Proposer: {}", self.proposer);
        println!("   Parent: {}", parent_hash);
        println!("   Pending TXs: {}", txs.len());
        println!("═══════════════════════════════════════════════════════════");

        let mut receipts = Vec::new();
        let mut total_gas_used = 0u64;

        // -------------------------------------------------------------
        // 1) SORT TX BY NONCE (absolutely required!)
        // -------------------------------------------------------------
        let mut txs_sorted = txs.clone();
        txs_sorted.sort_by_key(|tx| {
            match &tx.payload {
                TxPayload::Transfer { nonce, .. }
                | TxPayload::Stake { nonce, .. }
                | TxPayload::Unstake { nonce, .. }
                | TxPayload::ClaimReward { nonce, .. }
                | TxPayload::StorageOperationPayment { nonce, .. }
                | TxPayload::ComputeExecutionPayment { nonce, .. }
                | TxPayload::ValidatorRegistration { nonce, .. }
                | TxPayload::RegisterServiceNode { nonce, .. }
                | TxPayload::GovernanceAction { nonce, .. }
                => *nonce,

                TxPayload::Custom { nonce, .. } => *nonce,
            }
        });

        // -------------------------------------------------------------
        // 2) Apply TXs in correct nonce order
        // -------------------------------------------------------------
        for tx in &txs_sorted {
            let tx_hash = tx.compute_txid()?;
            
            // === ANTI SELF-DEALING CHECK (13.7.E) - RECIPIENT ONLY ===
            // Only check recipient-based self-dealing (Storage/Compute payments)
            // Sender-based self-dealing is handled in apply_payload with fee → treasury
            use crate::tx::TxPayload;

            let is_payment_tx = matches!(
                tx.payload,
                TxPayload::StorageOperationPayment { .. }
                    | TxPayload::ComputeExecutionPayment { .. }
            );

            // Anti self-dealing HANYA untuk payment tx
            if is_payment_tx && state.is_self_dealing(&self.proposer, &tx.payload) {
                println!(
                    "⛔ Self-dealing detected! Validator {} cannot receive payment from tx",
                    self.proposer
                );
                receipts.push(Receipt {
                    tx_hash,
                    success: false,
                    gas_used: 0,
                    events: vec!["self_dealing_rejected".to_string()],
                });
                continue;
            }


            // === EXECUTE TRANSACTION ===
            match state.apply_payload(tx, &self.proposer) {
                Ok((gas_used, events)) => {
                    total_gas_used = total_gas_used.saturating_add(gas_used);
                    receipts.push(Receipt {
                        tx_hash,
                        success: true,
                        gas_used,
                        events,
                    });
                }
                Err(e) => {
                    println!("❌ TX execution failed: {}", e);
                    receipts.push(Receipt {
                        tx_hash,
                        success: false,
                        gas_used: 0,
                        events: vec![format!("execution_failed: {}", e)],
                    });
                }
            }
        }

        // -------------------------------------------------------------
        // 2.5) AUTOMATIC SLASHING HOOK (13.14.6)
        // -------------------------------------------------------------
        // POSISI WAJIB: Setelah TX execution, SEBELUM state_root
        // Block producer HARUS menjalankan slashing di titik yang sama
        // dengan full node untuk menjaga determinisme
        // -------------------------------------------------------------
        //
        // Capture block timestamp ONCE for all post-TX hooks.
        // This ensures slashing and challenge processing use the
        // same time value, matching what full nodes see in
        // block.header.timestamp after the block is built.
        let block_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let slashing_events = state.process_automatic_slashing(height, block_time);
        
        if !slashing_events.is_empty() {
            println!("⚔️ SLASHING EXECUTED IN BLOCK:");
            for event in &slashing_events {
                println!("   └─ {:?}: {} slashed {} (treasury={}, burned={})",
                    event.reason,
                    event.target,
                    event.amount_slashed,
                    event.amount_to_treasury,
                    event.amount_burned
                );
            }
        }

        // -------------------------------------------------------------
        // 2.6) CHALLENGE PERIOD PROCESSING (CH.6)
        // -------------------------------------------------------------
        // POSISI WAJIB: Setelah slashing, SEBELUM state_root.
        //
        // Processes expired challenge periods for compute receipts:
        // - Pending + expired → mark cleared, distribute reward, remove
        // - Challenged + expired → report PendingResolution (no mutation)
        // - Terminal (Cleared/Slashed) → skip (idempotent)
        //
        // CONSENSUS-CRITICAL: pending_challenges termasuk dalam state_root.
        // Block producer HARUS memanggil ini pada posisi yang SAMA dengan
        // full node (apply_block_without_mining step 5.7) untuk menghasilkan
        // state_root identik.
        //
        // Idempotent: memanggil dua kali pada block yang sama tidak
        // mengubah state tambahan.
        // -------------------------------------------------------------
        let challenge_resolutions = crate::challenge_manager::process_expired_challenges(
            state,
            block_time,
        );

        if !challenge_resolutions.is_empty() {
            println!("🔔 CHALLENGE RESOLUTIONS IN BLOCK:");
            for resolution in &challenge_resolutions {
                match resolution {
                    crate::challenge_manager::ChallengeResolution::Cleared { .. } => {
                        println!("   └─ Cleared (reward released)");
                    }
                    crate::challenge_manager::ChallengeResolution::PendingResolution { .. } => {
                        println!("   └─ PendingResolution (awaiting dispute)");
                    }
                    crate::challenge_manager::ChallengeResolution::Slashed { amount, .. } => {
                        println!("   └─ Slashed (amount={})", amount);
                    }
                }
            }
        }

        // -------------------------------------------------------------
        // 3) Compute new state_root
        // -------------------------------------------------------------
        let state_root = state.compute_state_root()?;

        // -------------------------------------------------------------
        // 4) Block Production Summary (13.7.E) - BEFORE moving values
        // -------------------------------------------------------------
        let successful_txs = receipts.iter().filter(|r| r.success).count();
        let failed_txs = receipts.iter().filter(|r| !r.success).count();
        let total_txs = receipts.len();
        let state_root_display = format!("{}", state_root);
        
        println!("═══════════════════════════════════════════════════════════");
        println!("✅ BLOCK PRODUCTION COMPLETE - Height: {}", height);
        println!("   Total TXs: {} (Success: {}, Failed: {})", 
                 total_txs, successful_txs, failed_txs);
        println!("   Total Gas Used: {}", total_gas_used);
        println!("   State Root: {}", state_root_display);
        println!("───────────────────────────────────────────────────────────");
        println!("📊 FEE POOLS (13.8.E):");
        println!("   Validator Fee Pool: {}", state.get_validator_fee_pool());
        println!("   Storage Fee Pool: {}", state.get_storage_fee_pool());
        println!("   Compute Fee Pool: {}", state.get_compute_fee_pool());
        println!("   Treasury Balance: {}", state.get_treasury_balance());
        println!("   Delegator Pool: {}", state.get_delegator_pool());
        println!("═══════════════════════════════════════════════════════════");


        // -------------------------------------------------------------
        // 5) Build block
        // -------------------------------------------------------------
        let block_gas_limit = 30_000_000u64; // 30M gas per block
        let mut block = Block::new(
            height,
            parent_hash,
            txs_sorted,   // <- always put sorted txs into block!
            state_root,
            self.proposer,
            self.public_key.clone(), // proposer_pubkey for verification (13.7.J)
            total_gas_used,
            block_gas_limit,
        );

        block.body.receipts = receipts;

        // -------------------------------------------------------------
        // 6) Sign block
        // -------------------------------------------------------------
        block.sign(&self.private_key)?;

        Ok(block)
    }
}