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


// ════════════════════════════════════════════════════════════════════════════
// CH.8 — RECEIPT V1 TOKENOMICS INTEGRATION
// ════════════════════════════════════════════════════════════════════════════
//
// These functions bridge the ReceiptV1 claim pipeline to the existing
// fee split infrastructure. They delegate to calculate_fee_by_resource_class()
// to maintain a single source of truth for percentage constants (70/20/10).
//
// WHY DELEGATION (NOT DUPLICATION):
//
// calculate_fee_by_resource_class() is the canonical fee split function
// (13.8.E + 13.9 Blueprint). RewardDistribution::compute() in dsdn_common
// uses the same constants (70/20/10) independently. These CH.8 functions
// provide the bridge so that:
//
// 1. ReceiptV1 rewards are computed via the same code path as transaction fees.
// 2. Any future change to percentage constants only needs to happen in one place.
// 3. Cross-verification between RewardDistribution and FeeSplit is possible.
//
// If the percentages ever diverge between dsdn_common::RewardDistribution
// and tokenomics::calculate_fee_by_resource_class, verify_distribution_consistency
// will detect the mismatch.
// ════════════════════════════════════════════════════════════════════════════

/// Computes a ReceiptV1 reward distribution using the existing fee split engine.
///
/// ## Delegation
///
/// This function does NOT reimplement the 70/20/10 split. It delegates
/// to [`calculate_fee_by_resource_class`] by mapping:
///
/// | `ReceiptType` | `ResourceClass` |
/// |---------------|-----------------|
/// | `Storage` | `ResourceClass::Storage` |
/// | `Compute` | `ResourceClass::Compute` |
///
/// This ensures a **single source of truth** for tokenomics constants.
/// If fee percentages change, the change propagates automatically to
/// ReceiptV1 reward calculations.
///
/// ## Anti-Self-Dealing
///
/// The `node_address` and `submitter` parameters are forwarded directly
/// to `calculate_fee_by_resource_class`, which applies the anti-self-dealing
/// rule: if `node_address == submitter`, `node_share` is redirected to
/// `treasury_share`.
///
/// ## Parameters
///
/// - `reward_base` — Total reward amount (maps to `total_fee`).
/// - `receipt_type` — `ReceiptType::Storage` or `ReceiptType::Compute`.
/// - `node_address` — Service node address (maps to `service_node`).
///   `None` if node is unknown (anti-self-dealing check skipped).
/// - `submitter` — Transaction sender address.
///
/// ## Returns
///
/// `FeeSplit` with `node_share`, `validator_share`, `treasury_share`
/// summing to `reward_base`.
///
/// ## Guarantees
///
/// - Pure function. No mutation. No side effects.
/// - Deterministic: same inputs → same outputs.
/// - No panic. No unwrap.
/// - `split.total() == reward_base` (invariant from `calculate_fee_by_resource_class`).
#[must_use]
pub fn calculate_receipt_v1_reward(
    reward_base: u128,
    receipt_type: &dsdn_common::receipt_v1::ReceiptType,
    node_address: Option<crate::types::Address>,
    submitter: &crate::types::Address,
) -> FeeSplit {
    use dsdn_common::receipt_v1::ReceiptType;

    // Map ReceiptType → ResourceClass.
    //
    // This is the ONLY place where the ReceiptType ↔ ResourceClass mapping
    // is defined. Both Storage and Compute receipts use the same 70/20/10
    // split as their corresponding ResourceClass.
    let resource_class = match receipt_type {
        ReceiptType::Storage => crate::tx::ResourceClass::Storage,
        ReceiptType::Compute => crate::tx::ResourceClass::Compute,
    };

    // Delegate to the canonical fee split function.
    // All percentage logic lives in calculate_fee_by_resource_class.
    calculate_fee_by_resource_class(reward_base, &resource_class, node_address, submitter)
}

/// Cross-checks a `FeeSplit` against a `RewardDistribution` for consistency.
///
/// ## Purpose
///
/// `RewardDistribution` (from `dsdn_common::claim_validation`) and `FeeSplit`
/// (from `tokenomics.rs`) compute the same 70/20/10 split independently.
/// This function verifies that both produce identical results for the same
/// input, detecting any drift between the two implementations.
///
/// ## Field Mapping
///
/// | `FeeSplit` | `RewardDistribution` |
/// |------------|----------------------|
/// | `node_share` | `node_reward` |
/// | `validator_share` | `validator_reward` |
/// | `treasury_share` | `treasury_reward` |
///
/// ## Returns
///
/// `true` if ALL three fields match exactly. `false` otherwise.
///
/// ## Guarantees
///
/// - Pure function. No mutation. No side effects.
/// - Deterministic.
/// - No panic. No unwrap.
/// - Compares ALL fields (no partial comparison).
#[must_use]
pub fn verify_distribution_consistency(
    fee_split: &FeeSplit,
    distribution: &dsdn_common::claim_validation::RewardDistribution,
) -> bool {
    fee_split.node_share == distribution.node_reward
        && fee_split.validator_share == distribution.validator_reward
        && fee_split.treasury_share == distribution.treasury_reward
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

    // ════════════════════════════════════════════════════════════════════
    // CH.8 — RECEIPT V1 TOKENOMICS INTEGRATION TESTS
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_receipt_v1_storage_normal() {
        use dsdn_common::receipt_v1::ReceiptType;
        use crate::types::Address;

        let submitter = Address::from_bytes([0x01; 20]);
        let node = Address::from_bytes([0x02; 20]); // Different from submitter

        let split = calculate_receipt_v1_reward(
            1000,
            &ReceiptType::Storage,
            Some(node),
            &submitter,
        );

        // Same as ResourceClass::Storage: 70/20/10.
        assert_eq!(split.node_share, 700);
        assert_eq!(split.validator_share, 200);
        assert_eq!(split.treasury_share, 100);
        assert_eq!(split.total(), 1000);
    }

    #[test]
    fn test_receipt_v1_compute_normal() {
        use dsdn_common::receipt_v1::ReceiptType;
        use crate::types::Address;

        let submitter = Address::from_bytes([0x01; 20]);
        let node = Address::from_bytes([0x02; 20]);

        let split = calculate_receipt_v1_reward(
            1000,
            &ReceiptType::Compute,
            Some(node),
            &submitter,
        );

        assert_eq!(split.node_share, 700);
        assert_eq!(split.validator_share, 200);
        assert_eq!(split.treasury_share, 100);
        assert_eq!(split.total(), 1000);
    }

    #[test]
    fn test_receipt_v1_anti_self_dealing() {
        use dsdn_common::receipt_v1::ReceiptType;
        use crate::types::Address;

        let addr = Address::from_bytes([0x01; 20]);
        // node == submitter → anti-self-dealing.
        let split = calculate_receipt_v1_reward(
            1000,
            &ReceiptType::Compute,
            Some(addr),
            &addr,
        );

        assert_eq!(split.node_share, 0);
        assert_eq!(split.validator_share, 200);
        assert_eq!(split.treasury_share, 800);
        assert_eq!(split.total(), 1000);
    }

    #[test]
    fn test_receipt_v1_no_node_address() {
        use dsdn_common::receipt_v1::ReceiptType;
        use crate::types::Address;

        let submitter = Address::from_bytes([0x01; 20]);
        let split = calculate_receipt_v1_reward(
            1000,
            &ReceiptType::Storage,
            None, // No node address → anti-self-dealing skipped.
            &submitter,
        );

        // Normal 70/20/10 (no anti-self-dealing without node).
        assert_eq!(split.node_share, 700);
        assert_eq!(split.validator_share, 200);
        assert_eq!(split.treasury_share, 100);
    }

    #[test]
    fn test_receipt_v1_zero_reward_base() {
        use dsdn_common::receipt_v1::ReceiptType;
        use crate::types::Address;

        let submitter = Address::from_bytes([0x01; 20]);
        let split = calculate_receipt_v1_reward(
            0,
            &ReceiptType::Storage,
            None,
            &submitter,
        );

        assert_eq!(split.node_share, 0);
        assert_eq!(split.validator_share, 0);
        assert_eq!(split.treasury_share, 0);
        assert_eq!(split.total(), 0);
    }

    #[test]
    fn test_receipt_v1_matches_resource_class_exactly() {
        use dsdn_common::receipt_v1::ReceiptType;
        use crate::tx::ResourceClass;
        use crate::types::Address;

        let submitter = Address::from_bytes([0x01; 20]);
        let node = Address::from_bytes([0x02; 20]);

        // ReceiptV1 path.
        let receipt_split = calculate_receipt_v1_reward(
            12345,
            &ReceiptType::Storage,
            Some(node),
            &submitter,
        );

        // Direct ResourceClass path.
        let resource_split = calculate_fee_by_resource_class(
            12345,
            &ResourceClass::Storage,
            Some(node),
            &submitter,
        );

        // Must be identical — same code path.
        assert_eq!(receipt_split.node_share, resource_split.node_share);
        assert_eq!(receipt_split.validator_share, resource_split.validator_share);
        assert_eq!(receipt_split.treasury_share, resource_split.treasury_share);
    }

    #[test]
    fn test_verify_distribution_consistency_match() {
        use dsdn_common::claim_validation::RewardDistribution;

        let split = FeeSplit {
            node_share: 700,
            validator_share: 200,
            treasury_share: 100,
        };
        let dist = RewardDistribution::compute(1000);

        assert!(verify_distribution_consistency(&split, &dist));
    }

    #[test]
    fn test_verify_distribution_consistency_mismatch_node() {
        use dsdn_common::claim_validation::RewardDistribution;

        let split = FeeSplit {
            node_share: 699, // Wrong!
            validator_share: 200,
            treasury_share: 100,
        };
        let dist = RewardDistribution::compute(1000);

        assert!(!verify_distribution_consistency(&split, &dist));
    }

    #[test]
    fn test_verify_distribution_consistency_mismatch_validator() {
        use dsdn_common::claim_validation::RewardDistribution;

        let split = FeeSplit {
            node_share: 700,
            validator_share: 199, // Wrong!
            treasury_share: 100,
        };
        let dist = RewardDistribution::compute(1000);

        assert!(!verify_distribution_consistency(&split, &dist));
    }

    #[test]
    fn test_verify_distribution_consistency_mismatch_treasury() {
        use dsdn_common::claim_validation::RewardDistribution;

        let split = FeeSplit {
            node_share: 700,
            validator_share: 200,
            treasury_share: 99, // Wrong!
        };
        let dist = RewardDistribution::compute(1000);

        assert!(!verify_distribution_consistency(&split, &dist));
    }

    #[test]
    fn test_verify_distribution_consistency_anti_self_dealing() {
        use dsdn_common::claim_validation::RewardDistribution;

        let split = FeeSplit {
            node_share: 0,
            validator_share: 200,
            treasury_share: 800,
        };
        let dist = RewardDistribution::with_anti_self_dealing(1000);

        assert!(verify_distribution_consistency(&split, &dist));
    }

    #[test]
    fn test_verify_distribution_consistency_zero() {
        use dsdn_common::claim_validation::RewardDistribution;

        let split = FeeSplit {
            node_share: 0,
            validator_share: 0,
            treasury_share: 0,
        };
        let dist = RewardDistribution::compute(0);

        assert!(verify_distribution_consistency(&split, &dist));
    }

    #[test]
    fn test_receipt_v1_and_distribution_agree() {
        use dsdn_common::receipt_v1::ReceiptType;
        use dsdn_common::claim_validation::RewardDistribution;
        use crate::types::Address;

        let submitter = Address::from_bytes([0x01; 20]);
        let node = Address::from_bytes([0x02; 20]);

        // ReceiptV1 via tokenomics.
        let split = calculate_receipt_v1_reward(
            1000,
            &ReceiptType::Storage,
            Some(node),
            &submitter,
        );

        // RewardDistribution via dsdn_common.
        let dist = RewardDistribution::compute(1000);

        // Both must agree (single source of truth verification).
        assert!(verify_distribution_consistency(&split, &dist));
    }
}