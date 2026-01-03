//! Internal pending unstake queue management
//! Dipindahkan dari state.rs untuk modularisasi

use crate::types::Address;
use anyhow::Result;
use std::collections::HashMap;
use super::{ChainState, UnstakeEntry};

impl ChainState {
    // ============================================================
    // PENDING UNSTAKE MANAGEMENT (13.8.G)
    // ============================================================

    /// Process all unlocked unstake entries
    /// Should be called at each block production with current timestamp
    /// Returns: (total_processed_count, total_amount_released)
    pub fn process_unstake_unlocks(&mut self, current_ts: u64) -> (usize, u128) {
        let mut total_processed: usize = 0;
        let mut total_released: u128 = 0;
        
        let addresses: Vec<Address> = self.pending_unstakes.keys().cloned().collect();
        
        for addr in addresses {
            if let Some(entries) = self.pending_unstakes.get_mut(&addr) {
                let (ready, pending): (Vec<_>, Vec<_>) = entries
                    .drain(..)
                    .partition(|e| e.is_unlocked(current_ts));
                
                *entries = pending;
                
                for entry in ready {
                    // ✅ DON'T TOUCH LOCKED (already reduced in unbond_with_delay)
                    // Just release to balance
                    let balance = self.balances.entry(addr).or_insert(0);
                    *balance = balance.saturating_add(entry.amount);
                    
                    // 13.8.F: Reset reward tracking if fully unstaked
                    let remaining_locked = *self.locked.get(&addr).unwrap_or(&0);
                    if remaining_locked == 0 {
                        self.reset_delegator_reward_tracking(&addr);
                    }
                    
                    total_processed += 1;
                    total_released += entry.amount;
                    
                    println!("✅ Unstake processed (13.8.G): {} received {} tokens", 
                            addr, entry.amount);
                }
            }
            
            if let Some(entries) = self.pending_unstakes.get(&addr) {
                if entries.is_empty() {
                    self.pending_unstakes.remove(&addr);
                }
            }
        }
        
        if total_processed > 0 {
            println!("📦 Processed {} unstake(s), released {} total", 
                    total_processed, total_released);
        }
        
        (total_processed, total_released)
    }

    /// Cancel pending unstake before unlock time (13.8.G)
    /// Returns the amount re-staked, or error if not found/already unlocked
    pub fn cancel_pending_unstake(
        &mut self, 
        delegator: &Address, 
        validator: &Address,
        amount: u128,
        current_ts: u64,
    ) -> Result<u128> {
        // Extract entry first (avoids borrow issues)
        let (entry, should_remove) = {
            let entries = self.pending_unstakes
                .get_mut(delegator)
                .ok_or_else(|| anyhow::anyhow!("no pending unstake found for {}", delegator))?;

            let idx = entries.iter().position(|e| {
                e.validator == *validator &&
                e.amount == amount &&
                !e.is_unlocked(current_ts)
            }).ok_or_else(|| anyhow::anyhow!("no matching pending unstake found"))?;

            let entry = entries.remove(idx);
            let should_remove = entries.is_empty();
            (entry, should_remove)
        };

        // Update validator_set global stake
        self.validator_set.update_stake(validator, entry.amount as i128);
        
        // Update legacy validators map
        if let Some(v) = self.validators.get_mut(validator) {
            v.stake = v.stake.saturating_add(entry.amount);
        }

        // Restore stake based on type
        if entry.is_validator_unstake {
            // Restore to validator_stakes
            let val_stake = self.validator_stakes.entry(*validator).or_insert(0);
            *val_stake = val_stake.saturating_add(entry.amount);
        } else {
            // Restore to delegations
            let validator_delegations = self.delegations
                .entry(*validator)
                .or_insert_with(HashMap::new);
            let delegator_amount = validator_delegations.entry(*delegator).or_insert(0);
            *delegator_amount = delegator_amount.saturating_add(entry.amount);
            
            // Restore delegator tracking
            let del_stake = self.delegator_stakes.entry(*delegator).or_insert(0);
            *del_stake = del_stake.saturating_add(entry.amount);
            self.delegator_to_validator.insert(*delegator, *validator);
        }

        self.update_qv_weight(delegator);
        self.update_validator_qv_weight(validator);

        if should_remove {
            self.pending_unstakes.remove(delegator);
        }

        println!(
            "🔄 Unstake cancelled (13.8.G): {} re-staked {} to {}",
            delegator, entry.amount, validator
        );

        Ok(entry.amount)
    }

    /// Get all pending unstakes for an address
    pub fn get_pending_unstakes(&self, addr: &Address) -> Vec<&UnstakeEntry> {
        self.pending_unstakes
            .get(addr)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Get total pending unstake amount for an address
    pub fn get_total_pending_unstake(&self, addr: &Address) -> u128 {
        self.pending_unstakes
            .get(addr)
            .map(|entries| entries.iter().map(|e| e.amount).sum())
            .unwrap_or(0)
    }

    /// Check if address has any pending unstakes
    pub fn has_pending_unstake(&self, addr: &Address) -> bool {
        self.pending_unstakes
            .get(addr)
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    }

    /// Get all pending unstakes in the system (for DB persistence)
    pub fn get_all_pending_unstakes(&self) -> &HashMap<Address, Vec<UnstakeEntry>> {
        &self.pending_unstakes
    }

    /// Set pending unstakes (for DB load)
    pub fn set_pending_unstakes(&mut self, unstakes: HashMap<Address, Vec<UnstakeEntry>>) {
        self.pending_unstakes = unstakes;
    }
}
