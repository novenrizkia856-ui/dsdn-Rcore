//! Epoch Rotation Module (13.7.L)
//!
//! Handles periodic validator set updates based on:
//! - Total stake
//! - Quadratic Voting (QV) weight
//! - Delegator contributions
//!
//! Epoch rotation occurs every EPOCH_INTERVAL blocks.

use crate::types::Address;
use crate::state::{ChainState, ValidatorInfo};
use crate::qv::{compute_validator_total_power, compute_voting_power, VALIDATOR_WEIGHT_PCT};
use anyhow::Result;
use serde::{Serialize, Deserialize};

/// Default epoch interval (blocks between validator set rotations)
pub const DEFAULT_EPOCH_INTERVAL: u64 = 120;

/// Maximum number of active validators in the set
pub const DEFAULT_MAX_VALIDATORS: usize = 150;

// ============================================================
// 13.8.F - EPOCH REWARD CONSTANTS
// ============================================================

/// Number of epochs per year (assuming ~1 epoch per day with 120 blocks/epoch)
/// Adjust based on actual block time
pub const EPOCHS_PER_YEAR: u64 = 365;

/// Blocks per year estimation (for fallback calculations)
/// Assuming 6-second blocks: 365 * 24 * 60 * 60 / 6 = 5,256,000
pub const BLOCKS_PER_YEAR: u64 = 5_256_000;

/// Calculate delegator reward for single epoch with annual cap enforcement (13.8.F)
/// 
/// Formula:
///   max_reward_per_epoch = annual_cap / EPOCHS_PER_YEAR
///   actual_reward = min(base_reward, remaining_cap, max_reward_per_epoch)
/// 
/// Parameters:
/// - stake: delegator's staked amount
/// - base_reward: reward amount from fee pool (before cap enforcement)
/// - already_accrued: total rewards already received this year
/// 
/// Returns: capped reward amount for this epoch
pub fn calculate_epoch_reward(
    stake: u128,
    base_reward: u128,
    already_accrued: u128,
) -> u128 {
    use crate::tokenomics::{delegator_annual_cap, delegator_remaining_cap};
    
    // Get annual cap for this stake amount
    let annual_cap = delegator_annual_cap(stake);
    
    // Max reward per epoch to stay within annual cap
    let max_per_epoch = annual_cap / (EPOCHS_PER_YEAR as u128);
    
    // Remaining cap for the year
    let remaining = delegator_remaining_cap(stake, already_accrued);
    
    // Actual reward is minimum of: base_reward, max_per_epoch, remaining cap
    let capped_reward = base_reward
        .min(max_per_epoch)
        .min(remaining);
    
    capped_reward
}

/// Calculate pro-rata epoch reward for delegator based on stake proportion
/// Returns (gross_reward, capped_reward)
pub fn calculate_delegator_epoch_reward(
    delegator_stake: u128,
    total_delegated: u128,
    pool_amount: u128,
    already_accrued: u128,
) -> (u128, u128) {
    if total_delegated == 0 {
        return (0, 0);
    }
    
    // Pro-rata share from pool
    let gross_reward = (pool_amount * delegator_stake) / total_delegated;
    
    // Apply annual cap
    let capped_reward = calculate_epoch_reward(delegator_stake, gross_reward, already_accrued);
    
    (gross_reward, capped_reward)
}
/// Epoch configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochConfig {
    /// Number of blocks per epoch
    pub interval: u64,
    /// Maximum validators in active set
    pub max_validators: usize,
}

impl Default for EpochConfig {
    fn default() -> Self {
        Self {
            interval: DEFAULT_EPOCH_INTERVAL,
            max_validators: DEFAULT_MAX_VALIDATORS,
        }
    }
}

impl EpochConfig {
    pub fn new(interval: u64, max_validators: usize) -> Self {
        Self { interval, max_validators }
    }
}

/// Epoch metadata tracked in state
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EpochInfo {
    /// Current epoch number
    pub epoch_number: u64,
    /// Block height when current epoch started
    pub start_height: u64,
    /// Number of active validators in current epoch
    pub active_validators: usize,
    /// Total stake in current epoch
    pub total_stake: u128,
}

impl EpochInfo {
    pub fn new() -> Self {
        Self {
            epoch_number: 0,
            start_height: 0,
            active_validators: 0,
            total_stake: 0,
        }
    }

    /// Update epoch info for new epoch
    pub fn rotate(&mut self, new_epoch: u64, height: u64, active_count: usize, total_stake: u128) {
        self.epoch_number = new_epoch;
        self.start_height = height;
        self.active_validators = active_count;
        self.total_stake = total_stake;
    }
}

/// Validator with computed voting power for ranking
#[derive(Debug, Clone)]
pub struct RankedValidator {
    pub info: ValidatorInfo,
    pub voting_power: u128,
    pub delegator_power: u128,
    pub total_power: u128,
}

/// Check if epoch should rotate at given height
pub fn should_rotate(height: u64, config: &EpochConfig) -> bool {
    // Rotate at height 0 (genesis) and every interval thereafter
    height > 0 && height % config.interval == 0
}

/// Compute epoch number from block height
pub fn compute_epoch_number(height: u64, config: &EpochConfig) -> u64 {
    if config.interval == 0 {
        return 0;
    }
    height / config.interval
}

/// Compute new validator set based on stake and QV
///
/// Ranking formula:
/// - Validator weight (80%): sqrt(validator_stake)
/// - Delegator weight (20%): sum of sqrt(each_delegator_stake)
/// - Total power = validator_weight + delegator_weight
///
/// Top N validators by total_power are selected
pub fn compute_new_validator_set(
    state: &ChainState,
    config: &EpochConfig,
) -> Result<Vec<RankedValidator>> {
    println!("═══════════════════════════════════════════════════════════");
    println!("🔄 EPOCH ROTATION: Computing new validator set");
    println!("   Max validators: {}", config.max_validators);
    println!("═══════════════════════════════════════════════════════════");

    let mut ranked_validators: Vec<RankedValidator> = Vec::new();

    // Iterate all registered validators
    for (addr, vinfo) in &state.validator_set.validators {
        // Skip slashed validators
        if state.is_validator_slashed(addr) {
            println!("   ⛔ Skipping slashed validator: {}", addr);
            continue;
        }

        // Get delegator stakes for this validator
        let delegator_stakes: Vec<u128> = state.delegations
            .get(addr)
            .map(|delegators| delegators.values().cloned().collect())
            .unwrap_or_default();

        // Compute voting power using QV formula
        let validator_stake = vinfo.stake;
        let total_power = compute_validator_total_power(validator_stake, &delegator_stakes);
        
        // Calculate individual contributions for reporting
        let validator_power = (compute_voting_power(validator_stake) * VALIDATOR_WEIGHT_PCT) / 100;
        let delegator_power = total_power.saturating_sub(validator_power);

        ranked_validators.push(RankedValidator {
            info: vinfo.clone(),
            voting_power: validator_power,
            delegator_power,
            total_power,
        });
    }

    // Sort by total_power descending
    ranked_validators.sort_by(|a, b| b.total_power.cmp(&a.total_power));

    // Take top N validators
    let selected: Vec<RankedValidator> = ranked_validators
        .into_iter()
        .take(config.max_validators)
        .collect();

    println!("   📊 Ranked {} validators, selected top {}", 
             state.validator_set.validators.len(), 
             selected.len());

    // Log top 5 for visibility
    for (i, rv) in selected.iter().take(5).enumerate() {
        println!("   #{}: {} | stake={} | vp={} | dp={} | total={}",
                 i + 1,
                 rv.info.address,
                 rv.info.stake,
                 rv.voting_power,
                 rv.delegator_power,
                 rv.total_power);
    }

    if selected.len() > 5 {
        println!("   ... and {} more validators", selected.len() - 5);
    }

    Ok(selected)
}

/// Apply epoch rotation to chain state
///
/// This function:
/// 1. Computes new validator rankings
/// 2. Deactivates validators not in top N
/// 3. Activates validators in top N
/// 4. Updates epoch metadata
pub fn apply_epoch_rotation(
    state: &mut ChainState,
    height: u64,
    config: &EpochConfig,
) -> Result<Vec<String>> {
    let new_epoch = compute_epoch_number(height, config);
    
    println!("═══════════════════════════════════════════════════════════");
    println!("🌅 EPOCH {} ROTATION at height {}", new_epoch, height);
    println!("═══════════════════════════════════════════════════════════");

    let mut events = Vec::new();

    // Compute new validator set
    let ranked = compute_new_validator_set(state, config)?;

    // Collect addresses of validators that should be active
    let active_addrs: std::collections::HashSet<Address> = ranked
        .iter()
        .map(|rv| rv.info.address)
        .collect();

    let mut activated_count = 0;
    let mut deactivated_count = 0;

    // Update validator statuses
    let all_validators: Vec<Address> = state.validator_set.validators.keys().cloned().collect();
    
    for addr in all_validators {
        let should_be_active = active_addrs.contains(&addr);
        
        if let Some(vinfo) = state.validator_set.validators.get_mut(&addr) {
            let was_active = vinfo.active;
            
            if should_be_active && !was_active {
                // Activate validator
                vinfo.active = true;
                activated_count += 1;
                events.push(format!("ValidatorActivated:addr={},epoch={}", addr, new_epoch));
                println!("   ✅ Activated: {}", addr);
            } else if !should_be_active && was_active {
                // Deactivate validator (not in top N)
                vinfo.active = false;
                deactivated_count += 1;
                events.push(format!("ValidatorDeactivated:addr={},epoch={}", addr, new_epoch));
                println!("   ❌ Deactivated: {}", addr);
            }
        }

        // Also sync with legacy validators map
        if let Some(v) = state.validators.get_mut(&addr) {
            v.active = active_addrs.contains(&addr);
        }
    }

    // Calculate total stake of active set
    let total_stake: u128 = ranked.iter().map(|rv| rv.info.stake).sum();

    // Update epoch info
    state.epoch_info.rotate(
        new_epoch,
        height,
        ranked.len(),
        total_stake,
    );

    println!("═══════════════════════════════════════════════════════════");
    println!("✅ EPOCH {} ROTATION COMPLETE", new_epoch);
    println!("   Active validators: {}", ranked.len());
    println!("   Activated: {}, Deactivated: {}", activated_count, deactivated_count);
    println!("   Total stake: {}", total_stake);
    println!("═══════════════════════════════════════════════════════════");

    events.push(format!(
        "EpochRotation:epoch={},height={},validators={},stake={}",
        new_epoch, height, ranked.len(), total_stake
    ));

    Ok(events)
}

/// Check and apply epoch rotation if needed
/// Returns events if rotation occurred, empty vec otherwise
pub fn maybe_rotate_epoch(
    state: &mut ChainState,
    height: u64,
    config: &EpochConfig,
) -> Result<Vec<String>> {
    if should_rotate(height, config) {
        apply_epoch_rotation(state, height, config)
    } else {
        Ok(Vec::new())
    }
}

/// Get current epoch number from state
pub fn get_current_epoch(state: &ChainState) -> u64 {
    state.epoch_info.epoch_number
}

/// Get blocks remaining until next epoch rotation
pub fn blocks_until_next_epoch(current_height: u64, config: &EpochConfig) -> u64 {
    if config.interval == 0 {
        return 0;
    }
    let next_epoch_height = ((current_height / config.interval) + 1) * config.interval;
    next_epoch_height.saturating_sub(current_height)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_rotate() {
        let config = EpochConfig::new(120, 150);
        
        assert!(!should_rotate(0, &config));   // Genesis, no rotation
        assert!(!should_rotate(1, &config));
        assert!(!should_rotate(119, &config));
        assert!(should_rotate(120, &config));  // First epoch boundary
        assert!(!should_rotate(121, &config));
        assert!(should_rotate(240, &config));  // Second epoch boundary
    }

    #[test]
    fn test_compute_epoch_number() {
        let config = EpochConfig::new(120, 150);
        
        assert_eq!(compute_epoch_number(0, &config), 0);
        assert_eq!(compute_epoch_number(119, &config), 0);
        assert_eq!(compute_epoch_number(120, &config), 1);
        assert_eq!(compute_epoch_number(239, &config), 1);
        assert_eq!(compute_epoch_number(240, &config), 2);
    }

    #[test]
    fn test_blocks_until_next_epoch() {
        let config = EpochConfig::new(120, 150);
        
        assert_eq!(blocks_until_next_epoch(0, &config), 120);
        assert_eq!(blocks_until_next_epoch(100, &config), 20);
        assert_eq!(blocks_until_next_epoch(120, &config), 120);
        assert_eq!(blocks_until_next_epoch(121, &config), 119);
    }

   #[test]
    fn test_epoch_info_rotate() {
        let mut info = EpochInfo::new();
        assert_eq!(info.epoch_number, 0);
        
        info.rotate(1, 120, 100, 5_000_000);
        assert_eq!(info.epoch_number, 1);
        assert_eq!(info.start_height, 120);
        assert_eq!(info.active_validators, 100);
        assert_eq!(info.total_stake, 5_000_000);
    }

    // ============================================================
    // 13.8.F EPOCH REWARD TESTS
    // ============================================================

    #[test]
    fn test_calculate_epoch_reward_basic() {
        // Stake: 100,000 → Annual cap: 1,000
        // Max per epoch: 1,000 / 365 ≈ 2
        let stake = 100_000;
        let base_reward = 100; // more than max per epoch
        let already_accrued = 0;
        
        let reward = calculate_epoch_reward(stake, base_reward, already_accrued);
        // Should be capped to max_per_epoch ≈ 2
        assert!(reward <= 3); // Allow for rounding
    }

    #[test]
    fn test_calculate_epoch_reward_at_cap() {
        // Stake: 100,000 → Annual cap: 1,000
        let stake = 100_000;
        let base_reward = 100;
        let already_accrued = 1_000; // Already at cap
        
        let reward = calculate_epoch_reward(stake, base_reward, already_accrued);
        assert_eq!(reward, 0); // Should be 0 since at cap
    }

    #[test]
    fn test_calculate_epoch_reward_near_cap() {
        // Stake: 100,000 → Annual cap: 1,000
        let stake = 100_000;
        let base_reward = 100;
        let already_accrued = 995; // Only 5 remaining
        
        let reward = calculate_epoch_reward(stake, base_reward, already_accrued);
        assert!(reward <= 5); // Should be capped to remaining
    }

    #[test]
    fn test_calculate_delegator_epoch_reward() {
        // Delegator has 50% of total delegation
        let delegator_stake = 100_000;
        let total_delegated = 200_000;
        let pool_amount = 1000;
        let already_accrued = 0;
        
        let (gross, capped) = calculate_delegator_epoch_reward(
            delegator_stake,
            total_delegated,
            pool_amount,
            already_accrued,
        );
        
        // Gross = 50% of 1000 = 500
        assert_eq!(gross, 500);
        // Capped should be <= max per epoch
        assert!(capped <= gross);
    }
}