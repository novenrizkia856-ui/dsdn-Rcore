//! transaction envelope, payload types and signing / id helpers
use serde::{Serialize, Deserialize};
use crate::types::{Address, Hash};
use crate::crypto::{sha3_512_bytes, address_from_pubkey_bytes, verify_signature};
use crate::receipt::{ResourceReceipt, ResourceType};
use crate::state::{ProposalType, ProposalStatus, VoteOption};
use anyhow::{Result, anyhow};

const MIN_GAS_LIMIT: u64 = 21000; // base gas like EVM
pub const GAS_PRICE: u128 = 1; // 1 wei per gas, simple (made pub for state.rs)

// === STAKE REQUIREMENTS 
pub use crate::tokenomics::{VALIDATOR_MIN_STAKE, DELEGATOR_MIN_STAKE};
// Legacy aliases
pub const MIN_VALIDATOR_STAKE: u128 = 50_000;
pub const MIN_DELEGATOR_STAKE: u128 = 100_000;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceClass {
    Transfer,
    Storage,
    Compute,
    Governance,
}

/// Governance action types for TxPayload::GovernanceAction (13.12.5)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GovernanceActionType {
    /// Create new governance proposal
    CreateProposal {
        proposal_type: ProposalType,
        title: String,
        description: String,
    },
    /// Cast vote on proposal
    CastVote {
        proposal_id: u64,
        vote: VoteOption,
    },
    /// Finalize proposal after voting period
    FinalizeProposal {
        proposal_id: u64,
    },
    /// Foundation veto (Bootstrap Mode)
    FoundationVeto {
        proposal_id: u64,
    },
    /// Foundation override result (Bootstrap Mode)
    FoundationOverride {
        proposal_id: u64,
        new_status: ProposalStatus,
    },
}

/// Payload variants for transactions
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum TxPayload {
    /// Transfer from -> to
    Transfer {
        from: Address,
        to: Address,
        amount: u128,
        fee: u128,
        nonce: u64,
        gas_limit: u64,
        resource_class: ResourceClass,
        metadata_flagged: bool,
    },

    /// Stake operations (Bond/Unbond)
    Stake {
        delegator: Address,
        validator: Address,
        amount: u128,
        fee: u128,
        nonce: u64,
        bond: bool, // true = bond, false = unbond
        gas_limit: u64,
        resource_class: ResourceClass,
        metadata_flagged: bool,
    },

    /// Unstake (separate for clarity, but can merge with Stake bond=false)
    Unstake {
        delegator: Address,
        validator: Address,
        amount: u128,
        fee: u128,
        nonce: u64,
        gas_limit: u64,
        resource_class: ResourceClass,
        metadata_flagged: bool,
    },

    /// Claim rewards
    ClaimReward {
        receipt: ResourceReceipt,
        fee: u128,
        nonce: u64,
        gas_limit: u64,
    },

    /// Payment for storage operations (DSDN upload chunk, etc.)
    StorageOperationPayment {
        from: Address,
        to_node: Address,
        amount: u128,
        fee: u128,
        nonce: u64,
        operation_id: Vec<u8>, // chunk hash or id
        gas_limit: u64,
        resource_class: ResourceClass,
        metadata_flagged: bool,
    },

    /// Payment for compute execution (DSDN WASM/microVM run)
    ComputeExecutionPayment {
        from: Address,
        to_node: Address,
        amount: u128,
        fee: u128,
        nonce: u64,
        execution_id: Vec<u8>, // job id
        gas_limit: u64,
        resource_class: ResourceClass,
        metadata_flagged: bool,
    },

    /// Register as validator
    ValidatorRegistration {
        from: Address,
        pubkey: Vec<u8>,
        min_stake: u128,
        fee: u128,
        nonce: u64,
        gas_limit: u64,
        resource_class: ResourceClass,
        metadata_flagged: bool,
    },

    /// Governance action (stub)
    GovernanceAction {
        from: Address,
        action: GovernanceActionType,
        fee: u128,
        nonce: u64,
        gas_limit: u64,
    },

    /// Custom for expansion
    Custom {
        call_type: String,
        payload: Vec<u8>,
        fee: u128,
        nonce: u64,
        gas_limit: u64,
        resource_class: ResourceClass,
        metadata_flagged: bool,
    },
}
#[derive(Debug, Clone)]
pub struct PrivateTxInfo {
    pub sender: Address,
    pub fee: u128,
    pub gas_limit: u64,
    pub nonce: u64,
    pub resource_class: ResourceClass,
}

/// Envelope holding payload + signer pubkey + signature
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TxEnvelope {
    pub payload: TxPayload,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub is_private: bool,
    #[serde(skip)]
    pub cached_id: Option<Hash>,
}



impl TxEnvelope {
    pub fn new_unsigned(payload: TxPayload) -> Self {
        Self {
            payload,
            pubkey: Vec::new(),
            signature: Vec::new(),
            is_private: false,
            cached_id: None,
        }
    }

    pub fn payload_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(&self.payload).map_err(Into::into)
    }

    pub fn sign_input_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&bincode::serialize(&self.payload)?);
        out.extend_from_slice(&self.pubkey);
        Ok(out)
    }

    pub fn compute_txid(&self) -> Result<Hash> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&bincode::serialize(&self.payload)?);
        buf.extend_from_slice(&self.pubkey);
        buf.extend_from_slice(&self.signature);
        Ok(Hash::from_bytes(sha3_512_bytes(&buf)))
    }

    pub fn txid_hex(&self) -> Result<String> {
        Ok(self.compute_txid()?.to_hex())
    }

    pub fn verify_signature(&self) -> Result<bool> {
        if self.pubkey.is_empty() || self.signature.is_empty() {
            return Ok(false);
        }
        let payload_bytes = self.payload_bytes()?;
        verify_signature(&self.pubkey, &payload_bytes, &self.signature)
    }

    pub fn sender_address(&self) -> Result<Option<Address>> {
            if self.pubkey.is_empty() {
                return Ok(None);
            }
            address_from_pubkey_bytes(&self.pubkey).map(Some)
        }

    /// Check if this transaction is private (encrypted payload)
    pub fn is_private(&self) -> bool {
        self.is_private
    }

    /// Mark transaction as private (for testing/CLI)
    pub fn set_private(&mut self, private: bool) {
        self.is_private = private;
    }

    /// Create a new private transaction
    pub fn new_private(payload: TxPayload) -> Self {
        Self {
            payload,
            pubkey: Vec::new(),
            signature: Vec::new(),
            is_private: true,
            cached_id: None,
        }
    }

    /// Get minimal validation info for private tx (13.7.F)
    /// Validator HANYA boleh mengakses: signature, nonce, fee, gas_limit
    /// Validator TIDAK boleh membaca: amount, to, payload details
    pub fn get_private_validation_info(&self) -> Option<PrivateTxInfo> {
        if !self.is_private {
            return None;
        }
        
        let (fee, gas_limit, nonce) = self.payload.get_blind_info();
        let sender = self.sender_address().ok().flatten()?;
        
        Some(PrivateTxInfo {
            sender,
            fee,
            gas_limit,
            nonce,
            resource_class: self.payload.resource_class(),
        })
    }

    pub fn validate_stateless(&self) -> Result<()> {
        if self.signature.is_empty() || self.pubkey.is_empty() {
            return Err(anyhow!("missing pubkey or signature"));
        }
        if !self.verify_signature()? {
            return Err(anyhow!("invalid signature"));
        }

        // === STAKE REQUIREMENTS VALIDATION (13.7.C) ===
        // Early rejection untuk tx yang tidak memenuhi minimum stake
        self.payload.validate_stake_requirements()?;

        // Private tx: skip sender mismatch checks (payload terenkripsi)
        if self.is_private {
            return Ok(());
        }

if let Some(sender) = self.sender_address()? {
            match &self.payload {
                TxPayload::Transfer { from, .. } => if &sender != from { Err(anyhow!("from mismatch"))? },
                TxPayload::Stake { delegator, .. } => if &sender != delegator { Err(anyhow!("delegator mismatch"))? },
                TxPayload::Unstake { delegator, .. } => if &sender != delegator { Err(anyhow!("delegator mismatch"))? },
                TxPayload::ClaimReward { receipt, .. } => {
                    // Validasi sender harus sama dengan node_address di receipt
                    if sender != receipt.node_address {
                        return Err(anyhow!("sender does not match receipt.node_address"));
                    }
                    // Validasi stateless untuk receipt fields
                    if receipt.reward_base == 0 {
                        return Err(anyhow!("receipt.reward_base must be greater than 0"));
                    }
                    if receipt.timestamp == 0 {
                        return Err(anyhow!("receipt.timestamp must be greater than 0"));
                    }
                },
                TxPayload::StorageOperationPayment { from, .. } => if &sender != from { Err(anyhow!("from mismatch"))? },
                TxPayload::ComputeExecutionPayment { from, .. } => if &sender != from { Err(anyhow!("from mismatch"))? },
                TxPayload::ValidatorRegistration { from, .. } => if &sender != from { Err(anyhow!("from mismatch"))? },
                TxPayload::GovernanceAction { from, .. } => if &sender != from { Err(anyhow!("from mismatch"))? },
                TxPayload::Custom { .. } => {},
            }
        }
        Ok(())
    }

    pub fn validate_stateful<F1, F2>(&self, mut get_balance: F1, mut get_nonce: F2) -> Result<()>
    where
        F1: FnMut(&Address) -> u128,
        F2: FnMut(&Address) -> u64,
    {
        // Private tx: minimal validation (nonce, balance, gas saja)
        if self.is_private {
            return self.validate_private_tx(get_balance, get_nonce);
        }

        // Ambil sender dulu untuk semua case (kecuali Custom)
        let sender: &Address = match &self.payload {
            TxPayload::Transfer { from, .. }
            | TxPayload::Stake { delegator: from, .. }
            | TxPayload::Unstake { delegator: from, .. }
            | TxPayload::StorageOperationPayment { from, .. }
            | TxPayload::ComputeExecutionPayment { from, .. }
            | TxPayload::ValidatorRegistration { from, .. }
            | TxPayload::GovernanceAction { from, .. } => from,

            TxPayload::ClaimReward { receipt, .. } => &receipt.node_address,

            TxPayload::Custom { .. } => {
                return self.validate_stateful_custom(get_balance, get_nonce);
            }
        };

        let (gas_limit, fee, nonce, extra_amount) = match &self.payload {
            TxPayload::Transfer { gas_limit, fee, nonce, amount, .. } => (*gas_limit, *fee, *nonce, *amount),
            TxPayload::Stake { gas_limit, fee, nonce, amount, .. } => (*gas_limit, *fee, *nonce, *amount),
            TxPayload::Unstake { gas_limit, fee, nonce, amount, .. } => (*gas_limit, *fee, *nonce, *amount),
            TxPayload::ClaimReward { gas_limit, fee, nonce, .. } => (*gas_limit, *fee, *nonce, 0u128),
            TxPayload::StorageOperationPayment { gas_limit, fee, nonce, amount, .. } => (*gas_limit, *fee, *nonce, *amount),
            TxPayload::ComputeExecutionPayment { gas_limit, fee, nonce, amount, .. } => (*gas_limit, *fee, *nonce, *amount),
            TxPayload::ValidatorRegistration { gas_limit, fee, nonce, min_stake, .. } => (*gas_limit, *fee, *nonce, *min_stake),
            TxPayload::GovernanceAction { gas_limit, fee, nonce, .. } => (*gas_limit, *fee, *nonce, 0),
            _ => unreachable!(),
        };

        // Cek gas limit
        if gas_limit < MIN_GAS_LIMIT {
            return Err(anyhow!("gas_limit too low"));
        }

        // Cek nonce
        let expected_nonce = get_nonce(sender) + 1;
        if nonce != expected_nonce {
            return Err(anyhow!("invalid nonce: expected {}, got {}", expected_nonce, nonce));
        }

        // Cek balance
        let gas_cost = (gas_limit as u128) * crate::tx::GAS_PRICE;
        let total_required = fee + extra_amount + gas_cost;
        let balance = get_balance(sender);

        if balance < total_required {
            return Err(anyhow!(
                "insufficient balance: have {}, need {} (amount: {} + fee: {} + gas_cost: {})",
                balance,
                total_required,
                extra_amount,
                fee,
                gas_cost
            ));
        }

        Ok(())
    }

    // Helper khusus untuk Custom agar borrow checker senang
    fn validate_stateful_custom<F1, F2>(&self, mut get_balance: F1, mut get_nonce: F2) -> Result<()>
    where
        F1: FnMut(&Address) -> u128,
        F2: FnMut(&Address) -> u64,
    {
        let sender = self.sender_address()?.ok_or_else(|| anyhow!("custom tx requires sender"))?;

        let (gas_limit, fee, nonce) = match &self.payload {
            TxPayload::Custom { gas_limit, fee, nonce, .. } => (*gas_limit, *fee, *nonce),
            _ => unreachable!(),
        };

        if gas_limit < MIN_GAS_LIMIT {
            return Err(anyhow!("gas_limit too low"));
        }

        let expected_nonce = get_nonce(&sender) + 1;
        if nonce != expected_nonce {
            return Err(anyhow!("invalid nonce: expected {}, got {}", expected_nonce, nonce));
        }

        let gas_cost = (gas_limit as u128) * crate::tx::GAS_PRICE;
        let total_required = fee + gas_cost;
        let balance = get_balance(&sender);

        if balance < total_required {
            return Err(anyhow!("insufficient balance for custom tx"));
        }

        Ok(())
    }
fn validate_private_tx<F1, F2>(&self, mut get_balance: F1, mut get_nonce: F2) -> Result<()>
    where
        F1: FnMut(&Address) -> u128,
        F2: FnMut(&Address) -> u64,
    {
        let sender = self.sender_address()?.ok_or_else(|| anyhow!("private tx requires sender"))?;

        // Untuk private tx, kita ambil minimal info dari payload
        // Asumsi: fee, nonce, gas_limit masih readable (tidak terenkripsi)
        let (gas_limit, fee, nonce) = match &self.payload {
            TxPayload::Transfer { gas_limit, fee, nonce, .. }
            | TxPayload::Stake { gas_limit, fee, nonce, .. }
            | TxPayload::Unstake { gas_limit, fee, nonce, .. }
            | TxPayload::ClaimReward { gas_limit, fee, nonce, .. }
            | TxPayload::StorageOperationPayment { gas_limit, fee, nonce, .. }
            | TxPayload::ComputeExecutionPayment { gas_limit, fee, nonce, .. }
            | TxPayload::ValidatorRegistration { gas_limit, fee, nonce, .. }
            | TxPayload::GovernanceAction { gas_limit, fee, nonce, .. }
            | TxPayload::Custom { gas_limit, fee, nonce, .. } => (*gas_limit, *fee, *nonce),
        };

        // Basic checks
        if gas_limit < MIN_GAS_LIMIT {
            return Err(anyhow!("gas_limit too low"));
        }

        let expected_nonce = get_nonce(&sender) + 1;
        if nonce != expected_nonce {
            return Err(anyhow!("invalid nonce: expected {}, got {}", expected_nonce, nonce));
        }

        // Balance check (fee + gas saja, karena amount terenkripsi)
        let gas_cost = (gas_limit as u128) * crate::tx::GAS_PRICE;
        let total_required = fee + gas_cost;
        let balance = get_balance(&sender);

        if balance < total_required {
            return Err(anyhow!("insufficient balance for private tx (fee + gas)"));
        }

        Ok(())
    }
}

impl TxPayload {
    pub fn with_resource_class(mut self, class: ResourceClass) -> Self {
        match &mut self {
            TxPayload::Transfer { resource_class, .. }
            | TxPayload::Stake { resource_class, .. }
            | TxPayload::Unstake { resource_class, .. }
            | TxPayload::StorageOperationPayment { resource_class, .. }
            | TxPayload::ComputeExecutionPayment { resource_class, .. }
            | TxPayload::ValidatorRegistration { resource_class, .. }
            | TxPayload::Custom { resource_class, .. } => {
                *resource_class = class;
            }
            TxPayload::ClaimReward { .. } => {
                // ClaimReward resource_class ditentukan oleh receipt.resource_type
            }
            TxPayload::GovernanceAction { .. } => {
                // GovernanceAction selalu ResourceClass::Governance, tidak bisa diubah
            }
        }
        self
    }

    pub fn resource_class(&self) -> ResourceClass {
        match self {
            TxPayload::Transfer { .. } => ResourceClass::Transfer,

            TxPayload::Stake { .. }
            | TxPayload::Unstake { .. }
            | TxPayload::ValidatorRegistration { .. }
            | TxPayload::GovernanceAction { .. }
            | TxPayload::Custom { .. } => ResourceClass::Governance,

            TxPayload::StorageOperationPayment { .. } => ResourceClass::Storage,

            TxPayload::ComputeExecutionPayment { .. } => ResourceClass::Compute,

            TxPayload::ClaimReward { receipt, .. } => {
                match receipt.resource_type {
                    ResourceType::Storage => ResourceClass::Storage,
                    ResourceType::Compute => ResourceClass::Compute,
                }
            }
        }
    }

    /// Check jika transaksi ini ditandai sebagai ilegal oleh compliance system
    pub fn is_flagged_illegal(&self) -> bool {
        match self {
            TxPayload::Transfer { metadata_flagged, .. }
            | TxPayload::Stake { metadata_flagged, .. }
            | TxPayload::Unstake { metadata_flagged, .. }
            | TxPayload::StorageOperationPayment { metadata_flagged, .. }
            | TxPayload::ComputeExecutionPayment { metadata_flagged, .. }
            | TxPayload::ValidatorRegistration { metadata_flagged, .. }
            | TxPayload::Custom { metadata_flagged, .. } => *metadata_flagged,
            TxPayload::GovernanceAction { .. } => false,
            TxPayload::ClaimReward { .. } => false,
        }
    }
    /// Extract nonce from payload (for mempool deduplication)
    pub fn get_nonce(&self) -> Option<u64> {
        match self {
            TxPayload::Transfer { nonce, .. }
            | TxPayload::Stake { nonce, .. }
            | TxPayload::Unstake { nonce, .. }
            | TxPayload::ClaimReward { nonce, .. }
            | TxPayload::StorageOperationPayment { nonce, .. }
            | TxPayload::ComputeExecutionPayment { nonce, .. }
            | TxPayload::ValidatorRegistration { nonce, .. }
            | TxPayload::GovernanceAction { nonce, .. }
            | TxPayload::Custom { nonce, .. } => Some(*nonce),
        }
    }

    /// Extract sender address from payload (for mempool deduplication)
    pub fn get_sender(&self) -> Option<Address> {
        match self {
            TxPayload::Transfer { from, .. } => Some(*from),
            TxPayload::Stake { delegator, .. } => Some(*delegator),
            TxPayload::Unstake { delegator, .. } => Some(*delegator),
            TxPayload::ClaimReward { receipt, .. } => Some(receipt.node_address),
            TxPayload::StorageOperationPayment { from, .. } => Some(*from),
            TxPayload::ComputeExecutionPayment { from, .. } => Some(*from),
            TxPayload::ValidatorRegistration { from, .. } => Some(*from),
            TxPayload::GovernanceAction { from, .. } => Some(*from),
            TxPayload::Custom { .. } => None,
        }
    }

    /// Validate stake requirements sebelum tx masuk mempool (13.7.C + 13.8.A + 13.8.B)
    /// Returns Ok(()) jika valid, Err jika tidak memenuhi minimum stake
    pub fn validate_stake_requirements(&self) -> Result<()> {
        match self {
            TxPayload::Stake { delegator, validator, amount, bond, .. } => {
                // Hanya cek untuk bond operation
                if *bond {
                    // Check minimum stake
                    if *amount < crate::tokenomics::DELEGATOR_MIN_STAKE {
                        return Err(anyhow!(
                            "stake below minimum: {} < {}",
                            amount,
                            crate::tokenomics::DELEGATOR_MIN_STAKE
                        ));
                    }
                    
                    // 13.8.B: External delegation additional check
                    // Note: Full validator registration check happens in state.rs
                    // Here we just do basic sanity check
                    if delegator != validator {
                        // This is external delegation - validator must exist
                        // (actual check in apply_payload)
                        println!("📋 External delegation request: {} → {}", delegator, validator);
                    }
                }
                Ok(())
            }
            TxPayload::ValidatorRegistration { min_stake, .. } => {
                // Use tokenomics constant (13.8.A)
                if *min_stake < crate::tokenomics::VALIDATOR_MIN_STAKE {
                    return Err(anyhow!(
                        "validator stake below minimum: {} < {}",
                        min_stake,
                        crate::tokenomics::VALIDATOR_MIN_STAKE
                    ));
                }
                Ok(())
            }
            // Payload lain tidak memerlukan stake validation
            _ => Ok(()),
        }
    }
   /// Check if this transaction type allows validator to receive fees (13.8.A)
    /// Compute/Storage transactions do NOT pay fees to validators
    pub fn is_validator_fee_eligible(&self) -> bool {
        crate::tokenomics::is_validator_fee_eligible(&self.resource_class())
    }

    // ============================================================
    // DELEGATION HELPERS (13.8.B)
    // ============================================================

    /// Check if this is a self-delegation (validator staking to themselves)
    /// vs external delegation (delegator staking to validator)
    pub fn is_self_delegation(&self) -> bool {
        match self {
            TxPayload::Stake { delegator, validator, .. } => delegator == validator,
            _ => false,
        }
    }

    /// Check if this is an external delegation (delegator != validator)
    pub fn is_external_delegation(&self) -> bool {
        match self {
            TxPayload::Stake { delegator, validator, bond, .. } => {
                *bond && delegator != validator
            }
            _ => false,
        }
    }

    /// Get delegation info (delegator, validator) if this is a stake tx
    pub fn get_delegation_info(&self) -> Option<(Address, Address)> {
        match self {
            TxPayload::Stake { delegator, validator, .. } => Some((*delegator, *validator)),
            TxPayload::Unstake { delegator, validator, .. } => Some((*delegator, *validator)),
            _ => None,
        }
    }

    // ============================================================
    // QV HELPERS (13.8.C)
    // ============================================================

    /// Get stake amount from payload (for QV calculation)
    pub fn get_stake_amount(&self) -> Option<u128> {
        match self {
            TxPayload::Stake { amount, .. } => Some(*amount),
            TxPayload::Unstake { amount, .. } => Some(*amount),
            TxPayload::ValidatorRegistration { min_stake, .. } => Some(*min_stake),
            _ => None,
        }
    }

    /// Check if this transaction affects QV weights
    /// Returns true for stake-related transactions
    pub fn affects_qv_weight(&self) -> bool {
        matches!(
            self,
            TxPayload::Stake { .. } 
            | TxPayload::Unstake { .. } 
            | TxPayload::ValidatorRegistration { .. }
        )
    }

    /// Get addresses that need QV weight update after this transaction
    /// Returns (primary_addr, optional_validator_addr)
    pub fn get_qv_update_addresses(&self) -> Option<(Address, Option<Address>)> {
        match self {
            TxPayload::Stake { delegator, validator, .. } => {
                Some((*delegator, Some(*validator)))
            }
            TxPayload::Unstake { delegator, validator, .. } => {
                Some((*delegator, Some(*validator)))
            }
            TxPayload::ValidatorRegistration { from, .. } => {
                Some((*from, Some(*from))) // validator is same as from
            }
            _ => None,
        }
    }



    // ============================================================
    // Private TX Helpers (13.7.F) - Extract minimal info only
    // ============================================================

    /// Extract minimal info required for blind validation (fee, gas_limit, nonce)
    /// Validator hanya boleh mengakses info ini untuk private tx
    pub fn get_blind_info(&self) -> (u128, u64, u64) {
        match self {
            TxPayload::Transfer { fee, gas_limit, nonce, .. }
            | TxPayload::Stake { fee, gas_limit, nonce, .. }
            | TxPayload::Unstake { fee, gas_limit, nonce, .. }
            | TxPayload::ClaimReward { fee, gas_limit, nonce, .. }
            | TxPayload::StorageOperationPayment { fee, gas_limit, nonce, .. }
            | TxPayload::ComputeExecutionPayment { fee, gas_limit, nonce, .. }
            | TxPayload::ValidatorRegistration { fee, gas_limit, nonce, .. }
            | TxPayload::GovernanceAction { fee, gas_limit, nonce, .. }
            | TxPayload::Custom { fee, gas_limit, nonce, .. } => (*fee, *gas_limit, *nonce),
        }
    }

    /// Get fee only (safe for private tx)
    pub fn get_fee(&self) -> u128 {
        self.get_blind_info().0
    }

    /// Get gas_limit only (safe for private tx)
    pub fn get_gas_limit(&self) -> u64 {
        self.get_blind_info().1
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_ed25519_keypair_bytes, address_from_pubkey_bytes};
    use crate::state::ChainState;

    #[test]
    fn test_transfer_sign_verify_and_stateful_validate() {
        let (pk, kp_bytes) = generate_ed25519_keypair_bytes();
        let from_addr = address_from_pubkey_bytes(&pk).expect("addr");
        let to_addr = Address::from_bytes([0x22u8;20]);
        let payload = TxPayload::Transfer {
            from: from_addr,
            to: to_addr,
            amount: 1_000,
            fee: 10,
            nonce: 1,
            gas_limit: 21000,
            resource_class: ResourceClass::Transfer,
            metadata_flagged: false,
        };
        let mut env = TxEnvelope::new_unsigned(payload.clone());
        env.pubkey = pk.clone();
        env.is_private = false;
        let payload_bytes = env.payload_bytes().expect("payload bytes");
        let sig = crate::crypto::sign_message_with_keypair_bytes(&kp_bytes, &payload_bytes).expect("sign");
        env.signature = sig;
        env.validate_stateless().expect("stateless ok");
        let mut st = ChainState::new();
        st.create_account(from_addr);
        st.create_account(to_addr);
        st.mint(&from_addr, 50_000).expect("mint"); // cukup untuk gas + fee + amount
        let get_balance = |a: &Address| st.get_balance(a);
        let get_nonce = |_a: &Address| -> u64 { 0u64 };
        env.validate_stateful(get_balance, get_nonce).expect("stateful ok");
    }
}