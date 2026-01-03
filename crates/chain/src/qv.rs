//! Quadratic Voting (QV) utilities for DPoS Hybrid consensus
//! 
//! Voting power = sqrt(stake)
//! Validator total power = 80% validator_power + 20% delegators_power

/// Integer square root menggunakan Newton-Raphson method
/// Mengembalikan floor(sqrt(x))
pub fn sqrt_u128(x: u128) -> u128 {
    if x == 0 {
        return 0;
    }
    if x == 1 {
        return 1;
    }
    
    // Initial guess: start with x/2 or a reasonable estimate
    let mut guess = x / 2;
    let mut result = guess;
    
    loop {
        // Newton-Raphson: next = (guess + x/guess) / 2
        let next = (guess + x / guess) / 2;
        
        if next >= guess {
            // Converged
            break;
        }
        
        result = next;
        guess = next;
    }
    
    result
}

/// Compute voting power dari stake menggunakan quadratic formula
/// voting_power = sqrt(stake)
#[inline]
pub fn compute_voting_power(stake: u128) -> u128 {
    sqrt_u128(stake)
}

/// Compute QV weight for governance voting (13.8.C)
/// QV weight = sqrt(total_stake)
/// This is stored in state and updated on every stake/unstake operation
#[inline]
pub fn compute_qv_weight(stake: u128) -> u128 {
    sqrt_u128(stake)
}

/// Compute combined QV weight for a validator including delegator influence
/// Formula: validator_qv (80%) + sum(delegator_qv) * 20%
pub fn compute_combined_qv_weight(
    validator_stake: u128,
    delegator_stakes: &[u128],
) -> u128 {
    // Validator's QV weight (80%)
    let validator_qv = compute_qv_weight(validator_stake);
    let validator_contribution = (validator_qv * VALIDATOR_WEIGHT_PCT) / 100;
    
    // Delegators' QV weight sum (20%)
    let delegators_qv_sum: u128 = delegator_stakes
        .iter()
        .map(|&stake| compute_qv_weight(stake))
        .sum();
    let delegator_contribution = (delegators_qv_sum * DELEGATOR_WEIGHT_PCT) / 100;
    
    validator_contribution.saturating_add(delegator_contribution)
}

/// Konstanta untuk weight distribution
pub const VALIDATOR_WEIGHT_PCT: u128 = 80;  // 80%
pub const DELEGATOR_WEIGHT_PCT: u128 = 20;  // 20%

/// Compute total voting power untuk validator dengan delegator
/// validator_power = 80% * sqrt(validator_stake) + 20% * sum(sqrt(delegator_stake_i))
pub fn compute_validator_total_power(
    validator_stake: u128,
    delegator_stakes: &[u128],
) -> u128 {
    // Validator's own voting power (80%)
    let validator_vp = compute_voting_power(validator_stake);
    let validator_contribution = (validator_vp * VALIDATOR_WEIGHT_PCT) / 100;
    
    // Delegators' voting power sum (20%)
    let delegators_vp_sum: u128 = delegator_stakes
        .iter()
        .map(|&stake| compute_voting_power(stake))
        .sum();
    let delegator_contribution = (delegators_vp_sum * DELEGATOR_WEIGHT_PCT) / 100;
    
    validator_contribution.saturating_add(delegator_contribution)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqrt_u128() {
        assert_eq!(sqrt_u128(0), 0);
        assert_eq!(sqrt_u128(1), 1);
        assert_eq!(sqrt_u128(4), 2);
        assert_eq!(sqrt_u128(9), 3);
        assert_eq!(sqrt_u128(16), 4);
        assert_eq!(sqrt_u128(100), 10);
        assert_eq!(sqrt_u128(10000), 100);
        assert_eq!(sqrt_u128(1000000), 1000);
        // Test non-perfect squares (should return floor)
        assert_eq!(sqrt_u128(2), 1);
        assert_eq!(sqrt_u128(3), 1);
        assert_eq!(sqrt_u128(5), 2);
        assert_eq!(sqrt_u128(10), 3);
        assert_eq!(sqrt_u128(99), 9);
    }

    #[test]
    fn test_compute_voting_power() {
        assert_eq!(compute_voting_power(100_000_000), 10_000); // 1e8 -> 1e4
        assert_eq!(compute_voting_power(1_000_000_000_000), 1_000_000); // 1e12 -> 1e6
    }

    #[test]
    fn test_compute_validator_total_power() {
        let total = compute_validator_total_power(
            100_000_000,
            &[100_000_000, 400_000_000],
        );
        assert_eq!(total, 14000);
    }

    #[test]
    fn test_validator_only_power() {
        // Validator with no delegators
        // sqrt(100M) = 10000, 80% = 8000
        let power = compute_validator_total_power(100_000_000, &[]);
        assert_eq!(power, 8000);
    }

    #[test]
    fn test_qv_reduces_whale_advantage() {
        // Whale: 100M stake
        let whale = compute_validator_total_power(100_000_000, &[]);
        // Small: 1M stake
        let small = compute_validator_total_power(1_000_000, &[]);
        
        // Linear ratio would be 100:1
        // QV ratio should be sqrt(100):sqrt(1) = 10:1
        let ratio = whale as f64 / small as f64;
        assert!(ratio < 15.0, "QV should reduce whale advantage");
        assert!(ratio > 5.0, "But not too much");
    }

    #[test]
    fn test_delegator_contribution() {
        // Single large delegator
        let with_delegator = compute_validator_total_power(
            100_000_000,  // validator stake
            &[100_000_000],  // delegator stake
        );
        let without_delegator = compute_validator_total_power(100_000_000, &[]);
        
        // With delegator should be higher
        assert!(with_delegator > without_delegator);
        
        // Delegator adds 20% of their voting power
        // sqrt(100M) = 10000, 20% = 2000
        assert_eq!(with_delegator - without_delegator, 2000);
    }

    #[test]
    fn test_multiple_small_delegators_vs_one_large() {
        // One large delegator: 400M
        let one_large = compute_validator_total_power(
            100_000_000,
            &[400_000_000],
        );
        
        // Four small delegators: 100M each = 400M total
        let four_small = compute_validator_total_power(
            100_000_000,
            &[100_000_000, 100_000_000, 100_000_000, 100_000_000],
        );
        
        // QV: Four small should have MORE power than one large
        // One large: sqrt(400M) = 20000, 20% = 4000
        // Four small: 4 * sqrt(100M) = 4 * 10000 = 40000, 20% = 8000
        assert!(four_small > one_large, "QV should favor decentralization");
    }

    // ============================================================
    // QV WEIGHT TESTS (13.8.C)
    // ============================================================

    #[test]
    fn test_compute_qv_weight() {
        // QV weight = sqrt(stake)
        assert_eq!(compute_qv_weight(0), 0);
        assert_eq!(compute_qv_weight(1), 1);
        assert_eq!(compute_qv_weight(100), 10);
        assert_eq!(compute_qv_weight(10000), 100);
        assert_eq!(compute_qv_weight(100_000_000), 10_000);
        assert_eq!(compute_qv_weight(1_000_000_000_000), 1_000_000);
    }

    #[test]
    fn test_compute_combined_qv_weight() {
        // Validator 100M, no delegators
        // sqrt(100M) = 10000, 80% = 8000
        let validator_only = compute_combined_qv_weight(100_000_000, &[]);
        assert_eq!(validator_only, 8000);
        
        // Validator 100M, one delegator 100M
        // Validator: 80% * 10000 = 8000
        // Delegator: 20% * 10000 = 2000
        // Total: 10000
        let with_delegator = compute_combined_qv_weight(100_000_000, &[100_000_000]);
        assert_eq!(with_delegator, 10000);
    }

    #[test]
    fn test_qv_weight_equals_voting_power() {
        // QV weight should equal voting power
        for stake in [0, 1, 100, 10000, 100_000_000] {
            assert_eq!(compute_qv_weight(stake), compute_voting_power(stake));
        }
    }
}