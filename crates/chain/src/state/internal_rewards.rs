//! Internal reward distribution functions
//! Dipindahkan dari state.rs untuk modularisasi

use crate::types::Address;
use anyhow::Result;
use super::ChainState;

impl ChainState {
    /// Distribute pending delegator rewards for a validator
    /// Validator takes 20% commission, delegators get 80%
    /// Returns (validator_commission, total_distributed_to_delegators)
    pub fn distribute_delegator_rewards(&mut self, validator: &Address) -> Result<(u128, u128)> {
        // Get pending rewards for this validator
        let pending = self.pending_delegator_rewards.get(validator).copied().unwrap_or(0);
        if pending == 0 {
            return Ok((0, 0));
        }

        // Calculate split: validator 20%, delegators 80%
        let (validator_commission, delegator_net) = 
            crate::tokenomics::calculate_delegator_reward_split(pending);

        // Pay validator commission
        *self.balances.entry(*validator).or_insert(0) += validator_commission;

        // Get delegators for this validator
        let delegators = self.delegations.get(validator).cloned().unwrap_or_default();
        let total_delegated: u128 = delegators.iter()
            .filter(|(del, _)| *del != validator) // exclude self
            .map(|(_, &amt)| amt)
            .sum();

        if total_delegated > 0 {
            // Distribute proportionally to delegators
            for (delegator, &stake) in delegators.iter() {
                if delegator == validator {
                    continue; // skip self-delegation
                }
                // Proportional share: (stake / total_delegated) * delegator_net
                let share = (delegator_net * stake) / total_delegated;
                *self.balances.entry(*delegator).or_insert(0) += share;
            }
        }

        // Clear pending rewards
        self.pending_delegator_rewards.remove(validator);

        println!("🎁 Delegator rewards distributed for {}: commission={}, to_delegators={}", 
                 validator, validator_commission, delegator_net);

        Ok((validator_commission, delegator_net))
    }

    /// Add to pending delegator rewards for a validator
    pub fn add_pending_delegator_reward(&mut self, validator: &Address, amount: u128) {
        let pending = self.pending_delegator_rewards.entry(*validator).or_insert(0);
        *pending = pending.saturating_add(amount);
    }

    /// Get pending delegator rewards for a validator
    pub fn get_pending_delegator_rewards(&self, validator: &Address) -> u128 {
        *self.pending_delegator_rewards.get(validator).unwrap_or(&0)
    }

    // ============================================================
    // DELEGATOR REWARD TRACKING (13.8.F)
    // ============================================================

    /// Get delegator's accrued rewards for current year
    pub fn get_delegator_accrued(&self, delegator: &Address) -> u128 {
        *self.delegator_reward_accrued.get(delegator).unwrap_or(&0)
    }

    /// Get delegator's last reward epoch
    pub fn get_delegator_last_epoch(&self, delegator: &Address) -> u64 {
        *self.delegator_last_epoch.get(delegator).unwrap_or(&0)
    }

    /// Check and reset annual cap if new year started
    pub fn maybe_reset_annual_cap(&mut self) {
        let current_epoch = self.epoch_info.epoch_number;
        let epochs_per_year = crate::epoch::EPOCHS_PER_YEAR;
        
        // Check if a new year has started
        if current_epoch >= self.year_start_epoch + epochs_per_year {
            // Reset all accrued rewards
            self.delegator_reward_accrued.clear();
            self.year_start_epoch = current_epoch;
            println!("🗓️ Annual cap reset at epoch {} (new year)", current_epoch);
        }
    }

    /// Calculate capped reward for a delegator (13.8.F)
    /// Returns the actual reward after applying annual 1% cap
    pub fn calculate_capped_reward(
        &self,
        delegator: &Address,
        base_reward: u128,
    ) -> u128 {
        // Get stake directly from delegator_stakes map
        let stake = self.delegator_stakes.get(delegator).copied().unwrap_or(0);
        let already_accrued = self.get_delegator_accrued(delegator);
        
        // Calculate annual cap (1% of stake)
        let annual_cap = crate::tokenomics::delegator_annual_cap(stake);
        let remaining_cap = annual_cap.saturating_sub(already_accrued);
        
        // Return minimum of base_reward and remaining cap
        base_reward.min(remaining_cap)
    }

    /// Distribute epoch rewards to delegators with annual cap enforcement (13.8.F)
    /// Returns (total_distributed, total_returned_to_pool)
    pub fn distribute_epoch_rewards_capped(&mut self, validator: &Address) -> Result<(u128, u128)> {
        // Check and reset annual cap if needed
        self.maybe_reset_annual_cap();
        
        // Get pending rewards for this validator
        let pending = self.pending_delegator_rewards.get(validator).copied().unwrap_or(0);
        if pending == 0 {
            return Ok((0, 0));
        }
        
        // Calculate validator commission (20%)
        let (validator_commission, delegator_pool) = 
            crate::tokenomics::calculate_delegator_reward_split(pending);
        
        // Pay validator commission
        *self.balances.entry(*validator).or_insert(0) += validator_commission;
        
        // Get delegators for this validator
        let delegators = self.delegations.get(validator).cloned().unwrap_or_default();
        let total_delegated: u128 = delegators.iter()
            .filter(|(del, _)| *del != validator)
            .map(|(_, &amt)| amt)
            .sum();
        
        let mut total_distributed: u128 = 0;
        let mut total_returned: u128 = 0;
        let current_epoch = self.epoch_info.epoch_number;
        
        if total_delegated > 0 {
            for (delegator, &stake) in delegators.iter() {
                if delegator == validator {
                    continue;
                }
                
                // Calculate pro-rata share
                let gross_share = (delegator_pool * stake) / total_delegated;
                
                // Get accrued rewards
                let already_accrued = self.delegator_reward_accrued.get(delegator).copied().unwrap_or(0);
                
                // Calculate capped reward
                let capped_reward = crate::epoch::calculate_epoch_reward(
                    stake,
                    gross_share,
                    already_accrued,
                );
                
                // Pay capped reward to delegator
                if capped_reward > 0 {
                    *self.balances.entry(*delegator).or_insert(0) += capped_reward;
                    
                    // Update accrued tracking
                    let accrued = self.delegator_reward_accrued.entry(*delegator).or_insert(0);
                    *accrued = accrued.saturating_add(capped_reward);
                    
                    // Update last epoch
                    self.delegator_last_epoch.insert(*delegator, current_epoch);
                    
                    total_distributed += capped_reward;
                }
                
                // Track returned amount (exceeded cap)
                if gross_share > capped_reward {
                    total_returned += gross_share - capped_reward;
                }
            }
        }
        
        // Return excess to delegator pool
        if total_returned > 0 {
            self.delegator_pool += total_returned;
        }
        
        // Clear pending rewards
        self.pending_delegator_rewards.remove(validator);
        
        println!("🎁 Epoch rewards (capped): validator_commission={}, distributed={}, returned_to_pool={}",
                 validator_commission, total_distributed, total_returned);
        
        Ok((total_distributed, total_returned))
    }

    /// Reset delegator reward tracking on full unstake (13.8.F)
    pub fn reset_delegator_reward_tracking(&mut self, delegator: &Address) {
        self.delegator_reward_accrued.remove(delegator);
        self.delegator_last_epoch.remove(delegator);
        println!("🔄 Delegator {} reward tracking reset (full unstake)", delegator);
    }

    /// Get delegator annual cap status
    /// Returns (stake, annual_cap, accrued, remaining)
    pub fn get_delegator_cap_status(&self, delegator: &Address) -> (u128, u128, u128, u128) {
        let stake = self.get_delegator_stake(delegator);
        let annual_cap = crate::tokenomics::delegator_annual_cap(stake);
        let accrued = self.get_delegator_accrued(delegator);
        let remaining = crate::tokenomics::delegator_remaining_cap(stake, accrued);
        (stake, annual_cap, accrued, remaining)
    }

    pub fn claim_reward(&mut self, node: &Address, amount: u128) -> Result<()> {
        if amount == 0 || self.reward_pool < amount {
            anyhow::bail!("invalid reward or reward pool insufficient");
        }

        self.reward_pool = self.reward_pool.saturating_sub(amount);

        let bal = self.balances.entry(*node).or_insert(0);
        *bal = bal.saturating_add(amount);

        Ok(())
    }
}
