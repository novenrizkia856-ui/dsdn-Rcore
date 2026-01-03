//! Internal staking management functions
//! Dipindahkan dari state.rs untuk modularisasi

use crate::types::Address;
use anyhow::Result;
use std::collections::HashMap;
use super::{ChainState, Validator, ValidatorInfo, UnstakeEntry, UNSTAKE_DELAY_SECONDS};

impl ChainState {
    // ============================================================
    // VALIDATOR STAKE MANAGEMENT (13.8.A)
    // ============================================================

    /// Deposit stake as validator's own capital
    /// Moves from balance to validator_stakes (NOT delegations)
    pub fn deposit_validator_stake(&mut self, addr: &Address, amount: u128) -> Result<()> {
        if amount < crate::tokenomics::VALIDATOR_MIN_STAKE {
            anyhow::bail!(
                "validator stake too low: minimum {} required, got {}",
                crate::tokenomics::VALIDATOR_MIN_STAKE,
                amount
            );
        }
        // Check balance
        let balance = self.balances.entry(*addr).or_insert(0);
        if *balance < amount {
            anyhow::bail!("insufficient balance for validator stake deposit");
        }
        
        // Deduct from balance
        *balance -= amount;
        
        // Add to validator_stakes
        let stake = self.validator_stakes.entry(*addr).or_insert(0);
        *stake = stake.saturating_add(amount);
        
        // Also update locked for QV calculation
        let locked = self.locked.entry(*addr).or_insert(0);
        *locked = locked.saturating_add(amount);
        
        // 13.8.C: Update QV weights
        self.update_qv_weight(addr);
        self.update_validator_qv_weight(addr);
        
        println!("💎 Validator stake deposited: {} → {}", addr, amount);
        Ok(())
    }

    pub(crate) fn ensure_validator_exists(&self, validator: &Address) -> Result<()> {
        if self.validator_set.is_validator(validator) {
            Ok(())
        } else {
            anyhow::bail!("validator not found")
        }
    }

    /// Withdraw validator stake back to balance
    pub fn withdraw_validator_stake(&mut self, addr: &Address, amount: u128) -> Result<()> {
        let stake = self.validator_stakes.entry(*addr).or_insert(0);
        if *stake < amount {
            anyhow::bail!("insufficient validator stake to withdraw");
        }
        
        // Deduct from validator_stakes
        *stake -= amount;
        
        // Return to balance
        let balance = self.balances.entry(*addr).or_insert(0);
        *balance = balance.saturating_add(amount);
        
        // Update locked
        let locked = self.locked.entry(*addr).or_insert(0);
        *locked = locked.saturating_sub(amount);
        
        // 13.8.C: Update QV weights
        self.update_qv_weight(addr);
        self.update_validator_qv_weight(addr);
        
        Ok(())
    }

    /// Get validator's own stake (not delegations)
    pub fn get_validator_stake(&self, addr: &Address) -> u128 {
        *self.validator_stakes.get(addr).unwrap_or(&0)
    }

    /// Check if validator meets minimum stake requirement
    pub fn validator_meets_minimum(&self, addr: &Address) -> bool {
        self.get_validator_stake(addr) >= crate::tokenomics::VALIDATOR_MIN_STAKE
    }

    /// Get delegator's total staked amount
    pub fn get_delegator_stake(&self, addr: &Address) -> u128 {
        *self.delegator_stakes.get(addr).unwrap_or(&0)
    }

    /// Update delegator stake tracking
    pub fn update_delegator_stake(&mut self, addr: &Address, amount: i128) {
        let stake = self.delegator_stakes.entry(*addr).or_insert(0);
        if amount >= 0 {
            *stake = stake.saturating_add(amount as u128);
        } else {
            *stake = stake.saturating_sub(amount.unsigned_abs());
        }
    }

    // ============================================================
    // DELEGATOR STAKE MANAGEMENT (13.8.B)
    // ============================================================

    /// Register delegator stake to a validator
    /// Rules:
    /// 1. Minimum stake: 100,000 NUSA
    /// 2. Validator must be registered
    /// 3. Delegator cannot be a validator
    /// 4. Delegator can only delegate to ONE validator
    pub fn register_delegator_stake(
        &mut self, 
        delegator: &Address, 
        validator: &Address, 
        amount: u128
    ) -> Result<()> {
        // 1. Check minimum delegator stake
        if amount < crate::tokenomics::DELEGATOR_MIN_STAKE {
            anyhow::bail!(
                "delegator stake too low: minimum {} required, got {}",
                crate::tokenomics::DELEGATOR_MIN_STAKE,
                amount
            );
        }

        // 2. Check validator is registered
        if !self.validator_set.is_validator(validator) {
            anyhow::bail!(
                "validator {} is not registered",
                validator
            );
        }

        // 3. Check delegator is NOT a validator (delegator cannot be validator)
        if self.validator_set.is_validator(delegator) {
            anyhow::bail!(
                "address {} is already a validator and cannot delegate",
                delegator
            );
        }

        // 4. Check if delegator already delegated to another validator
        if let Some(existing_validator) = self.delegator_to_validator.get(delegator) {
            if existing_validator != validator {
                anyhow::bail!(
                    "delegator {} already delegated to validator {}. Undelegate first.",
                    delegator,
                    existing_validator
                );
            }
        }

        // 5. Check balance
        let balance = self.balances.entry(*delegator).or_insert(0);
        if *balance < amount {
            anyhow::bail!("insufficient balance for delegation");
        }

        // 6. Deduct from balance
        *balance -= amount;

        // 7. Update delegator_stakes (total staked by this delegator)
        let delegator_total = self.delegator_stakes.entry(*delegator).or_insert(0);
        *delegator_total = delegator_total.saturating_add(amount);

        // 8. Update delegator_to_validator mapping
        self.delegator_to_validator.insert(*delegator, *validator);

        // 9. Update locked
        let locked = self.locked.entry(*delegator).or_insert(0);
        *locked = locked.saturating_add(amount);

        // 10. Track in delegations map (validator -> delegator -> amount)
        let validator_delegations = self.delegations.entry(*validator).or_insert_with(HashMap::new);
        let delegator_amount = validator_delegations.entry(*delegator).or_insert(0);
        *delegator_amount = delegator_amount.saturating_add(amount);

        // 11. Update validator's total stake in validator_set
        self.validator_set.update_stake(validator, amount as i128);

        // 12. Also update legacy validators map
        if let Some(v) = self.validators.get_mut(validator) {
            v.stake = v.stake.saturating_add(amount);
        }

        // 13. 13.8.C: Update QV weights
        self.update_qv_weight(delegator);
        self.update_validator_qv_weight(validator);

        println!("📥 Delegator {} staked {} to validator {}", delegator, amount, validator);
        Ok(())
    }

    /// Withdraw delegator stake from validator
    pub fn withdraw_delegator_stake(
        &mut self,
        delegator: &Address,
        validator: &Address,
        amount: u128
    ) -> Result<()> {
        // 1. Check delegator has delegation to this validator
        let current_validator = self.delegator_to_validator.get(delegator);
        if current_validator != Some(validator) {
            anyhow::bail!(
                "delegator {} has no delegation to validator {}",
                delegator,
                validator
            );
        }

        // 2. Check delegator has enough stake
        let delegator_total = self.delegator_stakes.get(delegator).copied().unwrap_or(0);
        if delegator_total < amount {
            anyhow::bail!(
                "insufficient delegator stake: have {}, want to withdraw {}",
                delegator_total,
                amount
            );
        }

        // 3. Check delegation amount
        let delegation_amount = self.delegations
            .get(validator)
            .and_then(|dels| dels.get(delegator))
            .copied()
            .unwrap_or(0);
        if delegation_amount < amount {
            anyhow::bail!(
                "insufficient delegation to validator: have {}, want to withdraw {}",
                delegation_amount,
                amount
            );
        }

        // 4. Update delegator_stakes
        let stake = self.delegator_stakes.entry(*delegator).or_insert(0);
        *stake = stake.saturating_sub(amount);

        // 5. Update locked
        let locked = self.locked.entry(*delegator).or_insert(0);
        *locked = locked.saturating_sub(amount);

        // 6. Return to balance
        let balance = self.balances.entry(*delegator).or_insert(0);
        *balance = balance.saturating_add(amount);

        // 7. Update delegations map
        if let Some(validator_dels) = self.delegations.get_mut(validator) {
            if let Some(del_amount) = validator_dels.get_mut(delegator) {
                *del_amount = del_amount.saturating_sub(amount);
                if *del_amount == 0 {
                    validator_dels.remove(delegator);
                    // Also remove from delegator_to_validator if fully withdrawn
                    self.delegator_to_validator.remove(delegator);
                }
            }
            if validator_dels.is_empty() {
                self.delegations.remove(validator);
            }
        }

        // 8. Update validator_set
        self.validator_set.update_stake(validator, -(amount as i128));

        // 9. Update legacy validators map
        if let Some(v) = self.validators.get_mut(validator) {
            v.stake = v.stake.saturating_sub(amount);
        }

        // 10. 13.8.C: Update QV weights
        self.update_qv_weight(delegator);
        self.update_validator_qv_weight(validator);

        // 11. 13.8.F: Reset reward tracking if full unstake
        let remaining_stake = self.get_delegator_stake(delegator);
        if remaining_stake == 0 {
            self.reset_delegator_reward_tracking(delegator);
        }

        println!("📤 Delegator {} withdrew {} from validator {}", delegator, amount, validator);
        Ok(())
    }

    /// Get the validator a delegator has delegated to
    pub fn get_delegator_validator(&self, delegator: &Address) -> Option<&Address> {
        self.delegator_to_validator.get(delegator)
    }

    /// Check if address is a delegator (has active delegation)
    pub fn is_delegator(&self, addr: &Address) -> bool {
        self.delegator_to_validator.contains_key(addr)
    }

    /// Check if delegation is valid (delegator != validator)
    pub fn is_valid_delegation(&self, delegator: &Address, validator: &Address) -> bool {
        // Delegator cannot be the same as validator
        if delegator == validator {
            return false;
        }
        // Delegator cannot be a registered validator
        if self.validator_set.is_validator(delegator) {
            return false;
        }
        // Validator must be registered
        self.validator_set.is_validator(validator)
    }

    /// stake (bond) helper
    pub fn bond(&mut self, delegator: &Address, validator: &Address, amount: u128) -> Result<()> {
        // deduct from delegator balance
        let bal = self.balances.entry(*delegator).or_insert(0u128);
        if *bal < amount {
            anyhow::bail!("insufficient funds to bond");
        }
        *bal = bal.saturating_sub(amount);
        // increase locked/delegator locked
        let locked = self.locked.entry(*delegator).or_insert(0u128);
        *locked = locked.saturating_add(amount);
        // increase validator stake
        let v = self.validators.entry(*validator).or_insert(Validator {
            address: *validator,
            stake: 0u128,
            pubkey: Vec::new(),
            active: true,
        });
        v.stake = v.stake.saturating_add(amount);
        
        // Sync ke validator_set (DPoS Hybrid)
        self.validator_set.update_stake(validator, amount as i128);
        
        // Track delegation untuk QV calculation
        let validator_delegations = self.delegations.entry(*validator).or_insert_with(HashMap::new);
        let delegator_amount = validator_delegations.entry(*delegator).or_insert(0u128);
        *delegator_amount = delegator_amount.saturating_add(amount);
        
        // 13.8.C: Update QV weights
        self.update_qv_weight(delegator);
        self.update_validator_qv_weight(validator);
        
        Ok(())
    }

    /// unbond helper (naive immediate unbond -> moves locked back to balance)
    pub fn unbond(&mut self, delegator: &Address, validator: &Address, amount: u128) -> Result<()> {
        self.unbond_with_delay(delegator, validator, amount, None)
    }
    
    /// Internal unbond with timestamp parameter (for testing)
    pub fn unbond_with_delay(
        &mut self, 
        delegator: &Address, 
        validator: &Address, 
        amount: u128,
        current_ts: Option<u64>,
    ) -> Result<()> {
        // 1. Validator MUST exist
        if !self.validator_set.is_validator(validator) {
            anyhow::bail!("validator not found");
        }

        // 2. Check locked amount (SINGLE source for validation)
        let locked = self.locked.get(delegator).copied().unwrap_or(0);
        if locked < amount {
            anyhow::bail!("delegator locked insufficient");
        }

        // 3. Determine if self-unstake
        let is_validator_unstake = delegator == validator;

        // 4. Calculate unlock timestamp
        let now_ts = current_ts.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });
        let unlock_ts = now_ts + UNSTAKE_DELAY_SECONDS;

        let entry = UnstakeEntry::new(amount, unlock_ts, *validator, is_validator_unstake);

        // ============================================================
        // IMMEDIATE EFFECTS (SECURITY: reduce power immediately)
        // ============================================================

        // 5. ✅ REDUCE LOCKED IMMEDIATELY (security - voting power must drop now)
        let locked_entry = self.locked.entry(*delegator).or_insert(0);
        *locked_entry = locked_entry.saturating_sub(amount);
        if *locked_entry == 0 {
            self.locked.remove(delegator);
        }

        // 6. Update validator_set global stake (ALWAYS)
        self.validator_set.update_stake(validator, -(amount as i128));

        // 7. Update legacy validators map (ALWAYS)
        if let Some(v) = self.validators.get_mut(validator) {
            v.stake = v.stake.saturating_sub(amount);
        }

        // 8. Handle self-unbond vs delegator-unbond DIFFERENTLY
        if is_validator_unstake {
            // Self-unbond: reduce validator_stakes ONLY
            let current_val_stake = self.validator_stakes.get(validator).copied().unwrap_or(0);
            if current_val_stake < amount {
                anyhow::bail!("validator self-stake insufficient");
            }
            self.validator_stakes.insert(*validator, current_val_stake - amount);
        } else {
            // Delegator unbond: reduce delegations map ONLY
            if let Some(validator_delegations) = self.delegations.get_mut(validator) {
                if let Some(del_amt) = validator_delegations.get_mut(delegator) {
                    if *del_amt < amount {
                        anyhow::bail!("delegation amount insufficient");
                    }
                    *del_amt = del_amt.saturating_sub(amount);
                    if *del_amt == 0 {
                        validator_delegations.remove(delegator);
                    }
                } else {
                    anyhow::bail!("no delegation found");
                }
                if validator_delegations.is_empty() {
                    self.delegations.remove(validator);
                }
            } else {
                anyhow::bail!("no delegations to this validator");
            }
            
            // Update delegator_stakes tracking
            let del_stake = self.delegator_stakes.entry(*delegator).or_insert(0);
            *del_stake = del_stake.saturating_sub(amount);
            if *del_stake == 0 {
                self.delegator_stakes.remove(delegator);
                self.delegator_to_validator.remove(delegator);
            }
        }

        // 9. Update QV weights immediately
        self.update_qv_weight(delegator);
        self.update_validator_qv_weight(validator);

        // ============================================================
        // DEFERRED EFFECTS (money release after 7 days)
        // ============================================================

        self.pending_unstakes
            .entry(*delegator)
            .or_insert_with(Vec::new)
            .push(entry);

        println!(
            "⏳ Unstake pending (13.8.G): {} unstaking {} from validator {}",
            delegator, amount, validator
        );
        println!("   Unlock at: {} (in {} seconds)", unlock_ts, UNSTAKE_DELAY_SECONDS);

        Ok(())
    }

    
    /// Legacy immediate unbond (for internal use only, e.g. slashing)
    pub fn unbond_immediate(&mut self, delegator: &Address, validator: &Address, amount: u128) -> Result<()> {
        self.ensure_validator_exists(validator)?;

        let locked = self.locked.entry(*delegator).or_insert(0u128);
        if *locked < amount {
            anyhow::bail!("delegator locked insufficient");
        }
        *locked = locked.saturating_sub(amount);
        
        let bal = self.balances.entry(*delegator).or_insert(0u128);
        *bal = bal.saturating_add(amount);
        
        // Determine if self-unbond
        let is_validator_unstake = delegator == validator;
        
        // Update validator_set (ALWAYS)
        self.validator_set.update_stake(validator, -(amount as i128));
        
        // Update legacy validators map (ALWAYS)
        if let Some(v) = self.validators.get_mut(validator) {
            v.stake = v.stake.saturating_sub(amount);
        }
        
        // Handle self vs delegator differently
        if is_validator_unstake {
            // Self-unbond: reduce validator_stakes
            let current = self.validator_stakes.get(validator).copied().unwrap_or(0);
            if current < amount {
                anyhow::bail!("validator self-stake insufficient");
            }
            self.validator_stakes.insert(*validator, current - amount);
        } else {
            // Delegator unbond: reduce delegations
            if let Some(validator_delegations) = self.delegations.get_mut(validator) {
                if let Some(delegator_amount) = validator_delegations.get_mut(delegator) {
                    *delegator_amount = delegator_amount.saturating_sub(amount);
                    if *delegator_amount == 0 {
                        validator_delegations.remove(delegator);
                    }
                }
                if validator_delegations.is_empty() {
                    self.delegations.remove(validator);
                }
            }
            
            let del_stake = self.delegator_stakes.entry(*delegator).or_insert(0);
            *del_stake = del_stake.saturating_sub(amount);
            if *del_stake == 0 {
                self.delegator_stakes.remove(delegator);
                self.delegator_to_validator.remove(delegator);
            }
        }
        
        self.update_qv_weight(delegator);
        self.update_validator_qv_weight(validator);
        
        Ok(())
    }
}
