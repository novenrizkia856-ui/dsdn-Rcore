//! DSDN Tokenomics Constants (13.7.H + 13.8.A)
//! Fee distribution weights for block rewards and staking rules

/// Validator receives 70% of transaction fees
pub const FEE_VALIDATOR_WEIGHT: u128 = 70;

/// Delegator pool receives 20% of transaction fees
/// This pool is distributed to delegators based on their stake proportion
pub const FEE_DELEGATOR_WEIGHT: u128 = 20;

pub const FEE_TREASURY_WEIGHT: u128 = 10;

/// Total weight (must equal 100)
pub const FEE_TOTAL_WEIGHT: u128 = 100;

// ============================================================
// 13.8.E - FEE DISTRIBUTION BY RESOURCE CLASS
// ============================================================
// Transfer   → Validator 100%
// Governance → Validator 50%, Treasury 50%
// Storage    → Storage Node 100%
// Compute    → Compute Node 100%
// ============================================================

/// Governance: Validator receives 50%
pub const GOVERNANCE_VALIDATOR_WEIGHT: u128 = 50;

/// Governance: Treasury receives 50%
pub const GOVERNANCE_TREASURY_WEIGHT: u128 = 50;

pub const DELEGATOR_COMMISSION_RATE: u128 = 20;

// ============================================================
// 13.8.F - DELEGATOR ANNUAL CAP (≤ 1%)
// ============================================================

/// Maximum annual reward rate for delegators (1% = 100 basis points)
pub const DELEGATOR_ANNUAL_CAP_PERCENT: u128 = 1;

/// Basis points denominator (100% = 10000 basis points)
pub const BASIS_POINTS: u128 = 100;

/// Calculate maximum annual reward for a delegator based on stake
/// Annual cap = 1% of stake
/// Returns: stake * 0.01
pub fn delegator_annual_cap(stake: u128) -> u128 {
    (stake * DELEGATOR_ANNUAL_CAP_PERCENT) / BASIS_POINTS
}

/// Calculate remaining reward capacity for the year
/// Returns: max(0, annual_cap - already_accrued)
pub fn delegator_remaining_cap(stake: u128, already_accrued: u128) -> u128 {
    let cap = delegator_annual_cap(stake);
    cap.saturating_sub(already_accrued)
}

/// Check if delegator has reached annual cap
pub fn delegator_at_cap(stake: u128, already_accrued: u128) -> bool {
    already_accrued >= delegator_annual_cap(stake)
}


/// Fee split result for 13.8.E (Updated for 70/20/10 blueprint)
#[derive(Debug, Clone, Copy)]
pub struct FeeSplit {
    pub node_share: u128,
    pub validator_share: u128,
    pub treasury_share: u128,
}

impl FeeSplit {
    pub fn new() -> Self {
        Self {
            node_share: 0,
            validator_share: 0,
            treasury_share: 0,
        }
    }
    
    pub fn total(&self) -> u128 {
        self.node_share + self.validator_share + self.treasury_share
    }
}

/// Calculate fee split based on ResourceClass (13.8.E + 13.9 Blueprint)
/// 
/// Fee Distribution Rules (Updated Blueprint):
/// - Storage/Compute: Node 70%, Validator 20%, Treasury 10%
/// - Transfer/Governance/Stake: Validator 100%
/// 
/// Anti-self-dealing node rule:
/// - If service_node == sender, node_share is redirected to treasury
/// 
/// This function is PURE - no mutations, no side effects.
pub fn calculate_fee_by_resource_class(
    total_fee: u128,
    resource_class: &crate::tx::ResourceClass,
    service_node: Option<crate::types::Address>,
    sender: &crate::types::Address,
) -> FeeSplit {
    use crate::tx::ResourceClass;
    
    let mut split = FeeSplit::new();
    
    match resource_class {
        ResourceClass::Storage | ResourceClass::Compute => {
            // Blueprint 70/20/10 for Storage & Compute
            split.node_share = total_fee * 70 / 100;
            split.validator_share = total_fee * 20 / 100;
            split.treasury_share = total_fee - split.node_share - split.validator_share;
            
            // Anti-self-dealing node rule:
            // If service_node == sender, node_share goes to treasury
            if let Some(node) = service_node {
                if node == *sender {
                    split.treasury_share += split.node_share;
                    split.node_share = 0;
                }
            }
        }
        ResourceClass::Transfer | ResourceClass::Governance => {
            // Blueprint: 100% to validator
            split.node_share = 0;
            split.validator_share = total_fee;
            split.treasury_share = 0;
        }
    }
    
    split
}

// ============================================================
// STAKING CONSTANTS 
// ============================================================

/// Minimum stake required to become a validator (50,000 NUSA)
pub const VALIDATOR_MIN_STAKE: u128 = 50_000;

/// Minimum stake required for delegators (100,000 NUSA)
pub const DELEGATOR_MIN_STAKE: u128 = 100_000;

/// Validator commission rate from delegator rewards (20%)
pub const VALIDATOR_COMMISSION_RATE: u128 = 20;

/// Helper function to calculate fee split
/// Returns (validator_share, delegator_share, treasury_share)
pub fn calculate_fee_split(total_fee: u128) -> (u128, u128, u128) {
    let validator_share = total_fee * FEE_VALIDATOR_WEIGHT / FEE_TOTAL_WEIGHT;
    let delegator_share = total_fee * FEE_DELEGATOR_WEIGHT / FEE_TOTAL_WEIGHT;
    // Treasury gets remainder to handle rounding
    let treasury_share = total_fee - validator_share - delegator_share;
    
    (validator_share, delegator_share, treasury_share)
}

// ============================================================
// COMPUTE/STORAGE FEE ALLOCATION (13.8.A)
// ============================================================
// Validator TIDAK boleh menerima fee dari compute/storage transactions.
// Fee dari compute/storage langsung ke service provider (to_node).
// ============================================================

/// Fee allocation for compute/storage transactions
/// Validator does NOT receive these fees - goes to service node + pools
/// Returns (service_node_share, delegator_share, treasury_share)
pub fn calculate_fee_split_for_service(total_fee: u128) -> (u128, u128, u128) {
    // Service node (compute/storage provider) gets 70%
    let service_node_share = total_fee * FEE_VALIDATOR_WEIGHT / FEE_TOTAL_WEIGHT;
    // Delegator pool gets 20%
    let delegator_share = total_fee * FEE_DELEGATOR_WEIGHT / FEE_TOTAL_WEIGHT;
    // Treasury gets 10%
    let treasury_share = total_fee - service_node_share - delegator_share;
    
    (service_node_share, delegator_share, treasury_share)
}

/// Validator-only fee allocation (for validator fee pool)
/// Used for Transfer, Stake, Governance transactions
/// Returns (validator_share, delegator_share, treasury_share)
pub fn calculate_fee_split_validator_eligible(total_fee: u128) -> (u128, u128, u128) {
    calculate_fee_split(total_fee) // Same as standard split
}

/// Check if a ResourceClass allows validator to receive fees
pub fn is_validator_fee_eligible(resource_class: &crate::tx::ResourceClass) -> bool {
    match resource_class {
        crate::tx::ResourceClass::Transfer => true,
        crate::tx::ResourceClass::Governance => true,
        // Validator does NOT receive fees from compute/storage
        crate::tx::ResourceClass::Storage => false,
        crate::tx::ResourceClass::Compute => false,
    }
}

/// Calculate validator commission from delegator rewards
/// Returns commission amount (20% of delegator share)
pub fn calculate_validator_commission(delegator_reward: u128) -> u128 {
    delegator_reward * VALIDATOR_COMMISSION_RATE / 100
}

/// Calculate delegator reward split (13.8.E)
/// Validator takes 20% commission, delegator gets 80%
/// Returns (validator_commission, delegator_net_reward)
pub fn calculate_delegator_reward_split(gross_reward: u128) -> (u128, u128) {
    let validator_commission = (gross_reward * DELEGATOR_COMMISSION_RATE) / 100;
    let delegator_net = gross_reward - validator_commission;
    (validator_commission, delegator_net)
}

/// Get fee pool type for a ResourceClass
/// Returns: "validator", "storage", "compute", or "treasury"
pub fn get_fee_pool_type(resource_class: &crate::tx::ResourceClass) -> &'static str {
    use crate::tx::ResourceClass;
    match resource_class {
        ResourceClass::Transfer => "validator",
        ResourceClass::Governance => "validator_treasury",
        ResourceClass::Storage => "storage",
        ResourceClass::Compute => "compute",
    }
}

// ════════════════════════════════════════════════════════════════════════════
// 13.14.4 — SLASHING ALLOCATION
// ════════════════════════════════════════════════════════════════════════════

/// Calculate slashing allocation between treasury and burn.
///
/// Distributes slashed amount according to given ratios.
/// Guarantees: treasury + burn == amount (no rounding loss).
///
/// # Arguments
///
/// * `amount` - Total amount being slashed
/// * `treasury_ratio` - Percentage to treasury (0-100)
/// * `burn_ratio` - Percentage to burn (0-100)
///
/// # Returns
///
/// * `(u128, u128)` - (amount_to_treasury, amount_to_burn)
///
/// # Panics
///
/// Does NOT panic. Uses saturating arithmetic.
///
/// # Example
///
/// ```ignore
/// // 50/50 split of 1000 tokens
/// let (treasury, burn) = calculate_slash_allocation(1000, 50, 50);
/// assert_eq!(treasury, 500);
/// assert_eq!(burn, 500);
/// assert_eq!(treasury + burn, 1000);
/// ```
pub fn calculate_slash_allocation(
    amount: u128,
    treasury_ratio: u8,
    burn_ratio: u8,
) -> (u128, u128) {
    // Handle edge cases
    if amount == 0 {
        return (0, 0);
    }
    
    // Calculate total ratio
    let total_ratio = treasury_ratio as u128 + burn_ratio as u128;
    if total_ratio == 0 {
        // If both ratios are 0, everything goes to treasury (safety fallback)
        return (amount, 0);
    }
    
    // Calculate treasury portion
    let to_treasury = (amount * treasury_ratio as u128) / total_ratio;
    
    // Burn gets remainder (ensures no rounding loss)
    let to_burn = amount.saturating_sub(to_treasury);
    
    (to_treasury, to_burn)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_split_with_remainder() {
        // 1000 fee: 700 + 200 + 100 = 1000
        let (v, d, t) = calculate_fee_split(1000);
        assert_eq!(v + d + t, 1000);
    }

    #[test]
    fn test_staking_constants() {
        assert_eq!(VALIDATOR_MIN_STAKE, 50_000);
        assert_eq!(DELEGATOR_MIN_STAKE, 100_000);
        assert_eq!(VALIDATOR_COMMISSION_RATE, 20);
    }

    #[test]
    fn test_fee_split_for_service() {
        let (service, d, t) = calculate_fee_split_for_service(1000);
        assert_eq!(service, 700); // Service node gets 70%
        assert_eq!(d, 200);       // Delegator pool gets 20%
        assert_eq!(t, 100);       // Treasury gets 10%
        assert_eq!(service + d + t, 1000);
    }

    #[test]
    fn test_validator_fee_eligibility() {
        use crate::tx::ResourceClass;
        
        assert!(is_validator_fee_eligible(&ResourceClass::Transfer));
        assert!(is_validator_fee_eligible(&ResourceClass::Governance));
        assert!(!is_validator_fee_eligible(&ResourceClass::Storage));
        assert!(!is_validator_fee_eligible(&ResourceClass::Compute));
    }

    #[test]
    fn test_validator_commission() {
        // 20% commission from 1000 delegator reward = 200
        assert_eq!(calculate_validator_commission(1000), 200);
        assert_eq!(calculate_validator_commission(500), 100);
    }


    #[test]
    fn test_fee_split_calculation() {
        let (v, d, t) = calculate_fee_split(100);
        assert_eq!(v, 70);
        assert_eq!(d, 20);
        assert_eq!(t, 10);
        assert_eq!(v + d + t, 100);
    }


    #[test]
    fn test_fee_by_resource_class_transfer() {
        use crate::tx::ResourceClass;
        use crate::types::Address;
        let sender = Address::from_bytes([0x01u8; 20]);
        let split = calculate_fee_by_resource_class(1000, &ResourceClass::Transfer, None, &sender);
        assert_eq!(split.validator_share, 1000);  // 100% to validator
        assert_eq!(split.node_share, 0);
        assert_eq!(split.treasury_share, 0);
        assert_eq!(split.total(), 1000);
    }

    #[test]
    fn test_fee_by_resource_class_governance() {
        use crate::tx::ResourceClass;
        use crate::types::Address;
        let sender = Address::from_bytes([0x01u8; 20]);
        // Blueprint override: Governance now 100% to validator
        let split = calculate_fee_by_resource_class(1000, &ResourceClass::Governance, None, &sender);
        assert_eq!(split.validator_share, 1000);   // 100% to validator
        assert_eq!(split.treasury_share, 0);
        assert_eq!(split.node_share, 0);
        assert_eq!(split.total(), 1000);
    }

    #[test]
    fn test_fee_by_resource_class_storage_normal() {
        use crate::tx::ResourceClass;
        use crate::types::Address;
        let sender = Address::from_bytes([0x01u8; 20]);
        let service_node = Address::from_bytes([0x02u8; 20]); // Different from sender
        let split = calculate_fee_by_resource_class(1000, &ResourceClass::Storage, Some(service_node), &sender);
        // Blueprint 70/20/10
        assert_eq!(split.node_share, 700);       // 70% to node
        assert_eq!(split.validator_share, 200);  // 20% to validator
        assert_eq!(split.treasury_share, 100);   // 10% to treasury
        assert_eq!(split.total(), 1000);
    }

    #[test]
    fn test_fee_by_resource_class_compute_anti_self_dealing_node() {
        use crate::tx::ResourceClass;
        use crate::types::Address;
        let sender = Address::from_bytes([0x01u8; 20]);
        let service_node = Address::from_bytes([0x01u8; 20]); // Same as sender!
        let split = calculate_fee_by_resource_class(1000, &ResourceClass::Compute, Some(service_node), &sender);
        // Anti-self-dealing: node_share goes to treasury
        assert_eq!(split.node_share, 0);         // 0% (redirected to treasury)
        assert_eq!(split.validator_share, 200);  // 20% to validator
        assert_eq!(split.treasury_share, 800);   // 70% + 10% = 80% to treasury
        assert_eq!(split.total(), 1000);
    }

    #[test]
    fn test_fee_by_resource_class_compute_normal() {
        use crate::tx::ResourceClass;
        use crate::types::Address;
        let sender = Address::from_bytes([0x01u8; 20]);
        let service_node = Address::from_bytes([0x02u8; 20]); // Different from sender
        let split = calculate_fee_by_resource_class(1000, &ResourceClass::Compute, Some(service_node), &sender);
        // Blueprint 70/20/10
        assert_eq!(split.node_share, 700);       // 70% to node
        assert_eq!(split.validator_share, 200);  // 20% to validator
        assert_eq!(split.treasury_share, 100);   // 10% to treasury
        assert_eq!(split.total(), 1000);
    }

    #[test]
    fn test_delegator_reward_split() {
        // 1000 gross reward
        // Validator commission: 20% = 200
        // Delegator net: 80% = 800
        let (commission, net) = calculate_delegator_reward_split(1000);
        assert_eq!(commission, 200);
        assert_eq!(net, 800);
        assert_eq!(commission + net, 1000);
    }

    // ============================================================
    // 13.8.F ANNUAL CAP TESTS
    // ============================================================

    #[test]
    fn test_delegator_annual_cap() {
        // 1% of 100,000 = 1,000
        assert_eq!(delegator_annual_cap(100_000), 1_000);
        // 1% of 1,000,000 = 10,000
        assert_eq!(delegator_annual_cap(1_000_000), 10_000);
        // 1% of 10,000,000 = 100,000
        assert_eq!(delegator_annual_cap(10_000_000), 100_000);
    }

    #[test]
    fn test_delegator_remaining_cap() {
        let stake = 100_000;
        // Cap = 1,000
        // If already accrued 300, remaining = 700
        assert_eq!(delegator_remaining_cap(stake, 300), 700);
        // If already accrued 1,000, remaining = 0
        assert_eq!(delegator_remaining_cap(stake, 1_000), 0);
        // If already accrued more than cap, remaining = 0
        assert_eq!(delegator_remaining_cap(stake, 2_000), 0);
    }

#[test]
    fn test_delegator_at_cap() {
        let stake = 100_000;
        // Cap = 1,000
        assert!(!delegator_at_cap(stake, 0));
        assert!(!delegator_at_cap(stake, 500));
        assert!(!delegator_at_cap(stake, 999));
        assert!(delegator_at_cap(stake, 1_000));
        assert!(delegator_at_cap(stake, 1_500));
    }

    // ============================================================
    // 13.14.4 SLASHING ALLOCATION TESTS
    // ============================================================

    #[test]
    fn test_calculate_slash_allocation_50_50() {
        let (treasury, burn) = calculate_slash_allocation(1000, 50, 50);
        assert_eq!(treasury, 500);
        assert_eq!(burn, 500);
        assert_eq!(treasury + burn, 1000);
    }

    #[test]
    fn test_calculate_slash_allocation_no_loss() {
        // Test with odd number to ensure no rounding loss
        let (treasury, burn) = calculate_slash_allocation(1001, 50, 50);
        assert_eq!(treasury + burn, 1001);
    }

    #[test]
    fn test_calculate_slash_allocation_zero_amount() {
        let (treasury, burn) = calculate_slash_allocation(0, 50, 50);
        assert_eq!(treasury, 0);
        assert_eq!(burn, 0);
    }

    #[test]
    fn test_calculate_slash_allocation_100_treasury() {
        let (treasury, burn) = calculate_slash_allocation(1000, 100, 0);
        assert_eq!(treasury, 1000);
        assert_eq!(burn, 0);
    }

    #[test]
    fn test_calculate_slash_allocation_100_burn() {
        let (treasury, burn) = calculate_slash_allocation(1000, 0, 100);
        assert_eq!(treasury, 0);
        assert_eq!(burn, 1000);
    }

}