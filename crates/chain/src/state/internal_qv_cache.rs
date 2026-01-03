//! Internal Quadratic Voting weight management
//! Dipindahkan dari state.rs untuk modularisasi
//! PERHITUNGAN tetap menggunakan `crate::qv`

use crate::types::Address;
use crate::qv::{compute_voting_power, compute_validator_total_power, compute_qv_weight, compute_combined_qv_weight};
use super::ChainState;

impl ChainState {
    // ============================================================
    // QUADRATIC VOTING WEIGHT MANAGEMENT (13.8.C)
    // ============================================================

    /// Update QV weight for an address based on their locked stake
    /// Called on every stake/unstake operation
    pub fn update_qv_weight(&mut self, addr: &Address) {
        let locked_stake = self.get_locked(addr);
        let qv_weight = compute_qv_weight(locked_stake);
        
        if qv_weight > 0 {
            self.qv_weights.insert(*addr, qv_weight);
        } else {
            self.qv_weights.remove(addr);
        }
        
        println!("📊 QV Weight updated: {} → {} (stake={})", addr, qv_weight, locked_stake);
    }

    /// Update combined QV weight for a validator (including delegator influence)
    /// Called when validator or their delegators stake changes
    pub fn update_validator_qv_weight(&mut self, validator: &Address) {
        let self_stake = self.get_validator_stake(validator);
        
        // If validator_stakes not set, calculate from validator_set minus delegations
        let validator_stake = if self_stake > 0 {
            self_stake
        } else {
            // Fallback: calculate self-stake from total minus delegations
            let total = self.validator_set.get(validator).map(|v| v.stake).unwrap_or(0);
            let delegated = self.delegations
                .get(validator)
                .map(|dels| dels.iter()
                    .filter(|(del, _)| *del != validator)
                    .map(|(_, &amt)| amt)
                    .sum::<u128>())
                .unwrap_or(0);
            
            let calculated_self_stake = total.saturating_sub(delegated);
            
            // SYNC to validator_stakes for consistency
            if calculated_self_stake > 0 {
                self.validator_stakes.insert(*validator, calculated_self_stake);
            }
            
            calculated_self_stake
        };
        
        // Collect delegator stakes (excluding self-delegation)
        let delegator_stakes: Vec<u128> = self.delegations
            .get(validator)
            .map(|dels| {
                dels.iter()
                    .filter(|(del_addr, _)| *del_addr != validator)
                    .map(|(_, &amount)| amount)
                    .collect()
            })
            .unwrap_or_default();
        
        // Compute combined QV weight using 80/20 formula
        let combined_qv = compute_combined_qv_weight(validator_stake, &delegator_stakes);
        
        if combined_qv > 0 {
            self.validator_qv_weights.insert(*validator, combined_qv);
        } else {
            self.validator_qv_weights.remove(validator);
        }
        
        println!("📊 Validator QV Weight updated: {} → {} (own_stake={}, delegators={})", 
                validator, combined_qv, validator_stake, delegator_stakes.len());
    }

    /// Get QV weight for an address
    pub fn get_qv_weight(&self, addr: &Address) -> u128 {
        *self.qv_weights.get(addr).unwrap_or(&0)
    }

    /// Get combined QV weight for a validator
    pub fn get_validator_qv_weight(&self, validator: &Address) -> u128 {
        *self.validator_qv_weights.get(validator).unwrap_or(&0)
    }

    /// Recalculate all QV weights (for state recovery or migration)
    pub fn recalculate_all_qv_weights(&mut self) {
        // Clear existing weights
        self.qv_weights.clear();
        self.validator_qv_weights.clear();
        
        // Recalculate individual QV weights
        let addresses: Vec<Address> = self.locked.keys().cloned().collect();
        for addr in addresses {
            self.update_qv_weight(&addr);
        }
        
        // Recalculate validator combined QV weights
        let validators: Vec<Address> = self.validator_set.validators.keys().cloned().collect();
        for validator in validators {
            self.update_validator_qv_weight(&validator);
        }
        
        println!("🔄 All QV weights recalculated: {} addresses, {} validators", 
                 self.qv_weights.len(), self.validator_qv_weights.len());
    }

    // ============================================================
    // Quadratic Voting (QV) Power Functions
    // ============================================================

    /// Get voting power untuk address berdasarkan locked stake
    /// voting_power = sqrt(locked_stake)
    pub fn get_voting_power(&self, addr: &Address) -> u128 {
        let stake = self.get_locked(addr);
        compute_voting_power(stake)
    }

    /// Get total voting power untuk validator (termasuk delegator contribution)
    /// Formula: 80% * sqrt(validator_stake) + 20% * sum(sqrt(delegator_stake_i))
    /// 
    /// 13.8.D: Uses EXPLICIT validator_stakes (self stake) NOT validator_set.stake
    /// validator_set.stake includes delegations, validator_stakes is pure self-stake
    pub fn get_validator_total_power(&self, validator: &Address) -> u128 {
        if !self.validator_set.is_validator(validator) {
            return 0;
        }

        // Use validator_stakes for self-stake (EXPLICIT)
        let self_stake = self.get_validator_stake(validator);
        
        // Fallback to validator_set only if validator_stakes not set
        let validator_stake = if self_stake > 0 {
            self_stake
        } else {
            // Calculate from validator_set minus delegations
            let total = self.validator_set.get(validator).map(|v| v.stake).unwrap_or(0);
            let delegated = self.delegations
                .get(validator)
                .map(|dels| dels.iter()
                    .filter(|(del, _)| *del != validator)
                    .map(|(_, &amt)| amt)
                    .sum::<u128>())
                .unwrap_or(0);
            total.saturating_sub(delegated)
        };

        let delegator_stakes: Vec<u128> = self.delegations
            .get(validator)
            .map(|dels| {
                dels.iter()
                    .filter(|(del_addr, _)| *del_addr != validator)
                    .map(|(_, &amount)| amount)
                    .collect()
            })
            .unwrap_or_default();

        compute_validator_total_power(validator_stake, &delegator_stakes)
    }

    // ============================================================
    // VALIDATOR VOTING WEIGHT (13.8.D)
    // ============================================================

    /// Compute validator voting weight using 80/20 QV formula
    /// 
    /// Formula: weight = 0.8 * sqrt(self_stake) + 0.2 * sum(sqrt(delegator_stake_i))
    /// 
    /// This is the PRIMARY function for:
    /// - Proposer selection weight
    /// - Governance voting weight
    /// - Consensus voting weight
    /// 
    /// Uses cached validator_qv_weights if available, otherwise computes on-the-fly
    pub fn compute_validator_weight(&self, validator: &Address) -> u128 {
        // Try cached value first (13.8.C)
        if let Some(&cached_weight) = self.validator_qv_weights.get(validator) {
            if cached_weight > 0 {
                return cached_weight;
            }
        }
        
        // Compute on-the-fly if not cached
        self.get_validator_total_power(validator)
    }

    /// Get self-stake QV component (80%)
    /// Returns: 0.8 * sqrt(self_stake)
    pub fn get_validator_self_qv(&self, validator: &Address) -> u128 {
        let self_stake = self.get_validator_stake(validator);
        let qv = compute_qv_weight(self_stake);
        (qv * 80) / 100
    }

    /// Get delegator QV component (20%)
    /// Returns: 0.2 * sum(sqrt(delegator_stake_i))
    pub fn get_validator_delegator_qv(&self, validator: &Address) -> u128 {
        let delegator_stakes: Vec<u128> = self.delegations
            .get(validator)
            .map(|dels| {
                dels.iter()
                    .filter(|(del_addr, _)| *del_addr != validator)
                    .map(|(_, &amount)| amount)
                    .collect()
            })
            .unwrap_or_default();
        
        let delegator_qv_sum: u128 = delegator_stakes
            .iter()
            .map(|&stake| compute_qv_weight(stake))
            .sum();
        
        (delegator_qv_sum * 20) / 100
    }

    /// Get detailed breakdown of validator weight components
    /// Returns (self_stake, self_qv_80, delegator_count, delegator_qv_20, total_weight)
    pub fn get_validator_weight_breakdown(&self, validator: &Address) -> (u128, u128, usize, u128, u128) {
        let self_stake = self.get_validator_stake(validator);
        let self_qv_80 = self.get_validator_self_qv(validator);
        
        let delegator_count = self.delegations
            .get(validator)
            .map(|dels| dels.iter().filter(|(del, _)| *del != validator).count())
            .unwrap_or(0);
        
        let delegator_qv_20 = self.get_validator_delegator_qv(validator);
        let total_weight = self.compute_validator_weight(validator);
        
        (self_stake, self_qv_80, delegator_count, delegator_qv_20, total_weight)
    }

    /// Get all validators sorted by total voting power (for proposer selection)
    /// 13.8.D: Uses compute_validator_weight() with 80/20 QV formula
    pub fn get_validators_by_power(&self) -> Vec<(Address, u128)> {
        let mut validators_power: Vec<(Address, u128)> = self.validator_set
            .validators
            .iter()
            .filter(|(_, v)| v.active)
            .map(|(addr, _)| (*addr, self.compute_validator_weight(addr)))
            .collect();
        
        // Sort by power descending
        validators_power.sort_by(|a, b| b.1.cmp(&a.1));
        validators_power
    }

    /// Get total network voting power (sum of all active validators)
    pub fn get_total_network_power(&self) -> u128 {
        self.validators
            .keys()
            .filter(|addr| {
                self.validators.get(*addr)
                    .map(|v| v.active)
                    .unwrap_or(false)
            })
            .map(|addr| self.get_validator_total_power(addr))
            .sum()
    }

    /// Get validator's power ratio (untuk weighted random selection)
    /// Returns (power, total_power) untuk kalkulasi probabilitas
    pub fn get_validator_power_ratio(&self, validator: &Address) -> (u128, u128) {
        let power = self.get_validator_total_power(validator);
        let total = self.get_total_network_power();
        (power, total)
    }
}
