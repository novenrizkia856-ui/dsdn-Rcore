//! Internal models for state module
//! Dipindahkan dari state.rs untuk modularisasi

use crate::types::Address;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

// ============================================================
// UNSTAKE DELAY CONSTANTS (13.8.G)
// ============================================================
/// Unstake delay duration: 7 days in seconds
/// 7 * 24 * 60 * 60 = 604800 seconds
pub const UNSTAKE_DELAY_SECONDS: u64 = 604_800;

/// Pending unstake entry (13.8.G)
/// Tracks unstake requests that are waiting for the delay period
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnstakeEntry {
    /// Amount being unstaked
    pub amount: u128,
    /// Unix timestamp when unstake becomes claimable
    pub unlock_ts: u64,
    /// Validator address (for delegation tracking)
    pub validator: Address,
    /// Whether this is a validator self-unstake or delegator unstake
    pub is_validator_unstake: bool,
}

impl UnstakeEntry {
    pub fn new(amount: u128, unlock_ts: u64, validator: Address, is_validator_unstake: bool) -> Self {
        Self {
            amount,
            unlock_ts,
            validator,
            is_validator_unstake,
        }
    }
    
    /// Check if this unstake is ready to be processed
    pub fn is_unlocked(&self, current_ts: u64) -> bool {
        current_ts >= self.unlock_ts
    }
    
    /// Remaining seconds until unlock
    pub fn remaining_seconds(&self, current_ts: u64) -> u64 {
        self.unlock_ts.saturating_sub(current_ts)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Validator {
    pub address: Address,
    pub stake: u128,
    pub pubkey: Vec<u8>,
    pub active: bool,
}

/// ValidatorInfo untuk DPoS Hybrid — extended model
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ValidatorInfo {
    pub address: Address,
    pub pubkey: Vec<u8>,
    pub stake: u128,
    pub active: bool,
    pub moniker: Option<String>,
}

impl ValidatorInfo {
    pub fn new(address: Address, pubkey: Vec<u8>, stake: u128, moniker: Option<String>) -> Self {
        Self {
            address,
            pubkey,
            stake,
            active: true,
            moniker,
        }
    }
}

/// ValidatorSet — DPoS Hybrid validator registry
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ValidatorSet {
    pub validators: HashMap<Address, ValidatorInfo>,
}

impl ValidatorSet {
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
        }
    }

    /// Tambah atau update validator
    pub fn add_validator(&mut self, info: ValidatorInfo) {
        self.validators.insert(info.address, info);
    }

    /// Update stake validator (amount bisa positif atau negatif)
    pub fn update_stake(&mut self, address: &Address, amount: i128) -> bool {
        if let Some(v) = self.validators.get_mut(address) {
            if amount >= 0 {
                v.stake = v.stake.saturating_add(amount as u128);
            } else {
                v.stake = v.stake.saturating_sub(amount.unsigned_abs());
            }
            true
        } else {
            false
        }
    }

    /// Set status active/inactive validator
    pub fn set_active(&mut self, address: &Address, active: bool) -> bool {
        if let Some(v) = self.validators.get_mut(address) {
            v.active = active;
            true
        } else {
            false
        }
    }

    /// Get validator by address
    pub fn get(&self, address: &Address) -> Option<&ValidatorInfo> {
        self.validators.get(address)
    }

    /// Get mutable validator by address
    pub fn get_mut(&mut self, address: &Address) -> Option<&mut ValidatorInfo> {
        self.validators.get_mut(address)
    }

    /// Get top validators sorted by stake (descending), filtered by active only
    pub fn get_top_validators(&self, limit: usize) -> Vec<ValidatorInfo> {
        let mut active_validators: Vec<_> = self.validators
            .values()
            .filter(|v| v.active)
            .cloned()
            .collect();
        
        // Sort by stake descending
        active_validators.sort_by(|a, b| b.stake.cmp(&a.stake));
        
        active_validators.into_iter().take(limit).collect()
    }

    /// Get all active validators count
    pub fn active_count(&self) -> usize {
        self.validators.values().filter(|v| v.active).count()
    }

    /// Total stake dari semua active validators
    pub fn total_stake(&self) -> u128 {
        self.validators
            .values()
            .filter(|v| v.active)
            .map(|v| v.stake)
            .sum()
    }

    /// Check if address is registered validator
    pub fn is_validator(&self, address: &Address) -> bool {
        self.validators.contains_key(address)
    }

    /// Remove validator (untuk slashing atau voluntary exit)
    pub fn remove_validator(&mut self, address: &Address) -> Option<ValidatorInfo> {
        self.validators.remove(address)
    }
}