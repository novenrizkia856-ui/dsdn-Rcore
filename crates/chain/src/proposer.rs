//! Proposer Selection Engine (13.7.D)
//! Stake-weighted round-robin proposer selection using parent block hash as seed

use crate::types::{Address, Hash};
use crate::state::{ChainState, ValidatorInfo};

/// Load active validators from state
pub fn load_validator_list(state: &ChainState) -> Vec<ValidatorInfo> {
    state.validator_set
        .validators
        .values()
        .filter(|v| v.active)
        .cloned()
        .collect()
}

/// Compute stake weights for each validator
/// Returns Vec of (Address, weight) where weight = validator's total voting power
/// 
/// 13.8.D: Uses compute_validator_weight() with 80/20 QV formula
/// weight = 0.8 * sqrt(self_stake) + 0.2 * sum(sqrt(delegator_stake_i))
pub fn compute_stake_weights(state: &ChainState, validators: &[ValidatorInfo]) -> Vec<(Address, u128)> {
    validators
        .iter()
        .map(|v| {
            // 13.8.D: Use compute_validator_weight for 80/20 QV split
            let weight = state.compute_validator_weight(&v.address);
            (v.address, weight)
        })
        .filter(|(_, weight)| *weight > 0)
        .collect()
}

/// Convert Hash to u64 seed for random selection
fn hash_to_seed(hash: &Hash) -> u64 {
    let bytes = hash.as_bytes();
    // Take first 8 bytes and convert to u64
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes[0..8]);
    u64::from_be_bytes(arr)
}

/// Choose proposer using stake-weighted selection with seed mixing
/// 
/// Algorithm:
/// 1. Calculate cumulative weights
/// 2. Use seed to select a point in the cumulative range
/// 3. Binary search to find the validator at that point
pub fn choose_proposer(
    seed_hash: &Hash,
    weighted_list: &[(Address, u128)],
) -> Option<Address> {
    if weighted_list.is_empty() {
        return None;
    }

    // Single validator case - no selection needed
    if weighted_list.len() == 1 {
        return Some(weighted_list[0].0);
    }

    // Calculate total weight
    let total_weight: u128 = weighted_list.iter().map(|(_, w)| *w).sum();
    if total_weight == 0 {
        return None;
    }

    // Get seed from hash
    let seed = hash_to_seed(seed_hash);

    // Calculate selection point using seed
    // Mix with block height component from seed for better distribution
    let selection_point = (seed as u128) % total_weight;

    // Build cumulative weights and select
    let mut cumulative: u128 = 0;
    for (addr, weight) in weighted_list {
        cumulative += *weight;
        if selection_point < cumulative {
            return Some(*addr);
        }
    }

    // Fallback to last validator (shouldn't reach here normally)
    Some(weighted_list.last()?.0)
}

/// Select block proposer using QV-weighted random selection
/// 
/// 13.8.D: Uses compute_validator_weight() with 80/20 QV formula
/// weight = 0.8 * sqrt(self_stake) + 0.2 * sum(sqrt(delegator_stake_i))
/// 
/// This ensures proposer selection is weighted by QV power, not raw stake
pub fn select_block_proposer(state: &ChainState, seed: &Hash) -> Option<Address> {
    // Get active validators with their QV weights (NOT raw stake)
    let mut validators: Vec<(Address, u128)> = state.validator_set.validators
        .iter()
        .filter(|(_, v)| v.active)
        .map(|(addr, _)| {
            // 13.8.D: Use compute_validator_weight for 80/20 QV split
            let weight = state.compute_validator_weight(addr);
            (*addr, weight)
        })
        .collect();
    
    if validators.is_empty() {
        return None;
    }
    
    // Sort for determinism (by address)
    validators.sort_by_key(|(addr, _)| *addr);
    
    // Calculate total QV weight
    let total_weight: u128 = validators.iter().map(|(_, weight)| weight).sum();
    if total_weight == 0 {
        return None;
    }
    
    // Generate deterministic random value from seed (0 to total_weight-1)
    let hash_bytes = seed.as_bytes();
    let mut hash_val: u128 = 0;
    for i in 0..16 {
        hash_val = (hash_val << 8) | (hash_bytes[i] as u128);
    }
    let random_point = hash_val % total_weight;
    
    // Cumulative weight selection using QV weights
    let mut cumulative: u128 = 0;
    for (addr, weight) in &validators {  
        cumulative += weight;
        if random_point < cumulative {
            return Some(*addr);  
        }
    }
    
    // Fallback (should never reach here)
    Some(validators[0].0)  
}

/// Deterministic proposer selection for testing
/// Uses a fixed seed instead of parent_hash
/// 
/// 13.8.D: Uses compute_validator_weight() with 80/20 QV formula
pub fn select_block_proposer_deterministic(
    state: &ChainState,
    seed: u64,
) -> Option<Address> {
    let validators = load_validator_list(state);
    if validators.is_empty() {
        return None;
    }

    // 13.8.D: compute_stake_weights now uses QV formula
    let weighted_list = compute_stake_weights(state, &validators);
    if weighted_list.is_empty() {
        return None;
    }

    let mut sorted_weights = weighted_list;
    sorted_weights.sort_by(|a, b| a.0.cmp(&b.0));

    // Use seed directly instead of hash
    let total_weight: u128 = sorted_weights.iter().map(|(_, w)| *w).sum();
    if total_weight == 0 {
        return None;
    }

    let selection_point = (seed as u128) % total_weight;
    let mut cumulative: u128 = 0;
    for (addr, weight) in &sorted_weights {
        cumulative += *weight;
        if selection_point < cumulative {
            return Some(*addr);
        }
    }

    Some(sorted_weights.last()?.0)
}

/// Debug function to get proposer selection distribution
/// Useful for testing stake-weight fairness
pub fn debug_proposer_distribution(
    state: &ChainState,
    samples: usize,
) -> std::collections::HashMap<Address, usize> {
    let mut counts = std::collections::HashMap::new();
    
    for i in 0..samples {
        if let Some(addr) = select_block_proposer_deterministic(state, i as u64) {
            *counts.entry(addr).or_insert(0) += 1;
        }
    }
    
    counts
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_seed() {
        let hash = Hash::from_bytes([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let seed = hash_to_seed(&hash);
        assert_eq!(seed, 0x123456789abcdef0);
    }

    #[test]
    fn test_choose_proposer_single() {
        let addr = Address::from_bytes([0x01; 20]);
        let weighted = vec![(addr, 1000u128)];
        let hash = Hash::from_bytes([0u8; 64]);
        
        let result = choose_proposer(&hash, &weighted);
        assert_eq!(result, Some(addr));
    }

    #[test]
    fn test_choose_proposer_weighted() {
        let addr1 = Address::from_bytes([0x01; 20]);
        let addr2 = Address::from_bytes([0x02; 20]);
        // addr2 has 3x more stake, should be selected ~75% of the time
        let weighted = vec![
            (addr1, 1000u128),
            (addr2, 3000u128),
        ];

        // Test determinism - same hash = same result
        let hash1 = Hash::from_bytes([0x10; 64]);
        let result1a = choose_proposer(&hash1, &weighted);
        let result1b = choose_proposer(&hash1, &weighted);
        assert_eq!(result1a, result1b);
    }
}