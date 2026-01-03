//! Validator Liveness & Slashing Module (13.7.K + 13.14)
//!
//! Basic skeleton for tracking validator liveness and applying slashing
//! when validators miss too many blocks.
//!
//! Current implementation:
//! - Tracks missed_blocks counter per validator
//! - Marks validator as slashed when threshold exceeded
//! - Does NOT yet deduct stake (placeholder for future)
//!
//! ## 13.14 — Automatic Slashing (Non-Governance)
//!
//! This module defines constants and data structures for automatic slashing:
//! - Node slashing: liveness failure, data corruption, malicious behavior
//! - Validator slashing: double-sign, prolonged offline, malicious block
//! - Slashed tokens: 50% treasury, 50% burned
//! - Delegator stake: protected except on extreme protocol failure

use crate::types::Address;
use crate::state::ChainState;
use serde::{Serialize, Deserialize};

// ════════════════════════════════════════════════════════════════════════════
// LEGACY CONSTANTS (13.7.K)
// ════════════════════════════════════════════════════════════════════════════

/// Maximum consecutive missed blocks before slashing
pub const MAX_MISSED_BLOCKS: u64 = 50;

/// Percentage of stake to slash (for future implementation)
pub const SLASH_PERCENTAGE: u64 = 5; // 5% of stake

// ════════════════════════════════════════════════════════════════════════════
// 13.14.1 — SLASHING CONSTANTS (CONSENSUS-CRITICAL)
// ════════════════════════════════════════════════════════════════════════════
// All percentages are in BASIS POINTS (1 bp = 0.01%)
// Do NOT use floating point. Do NOT change values without hard-fork.
// ════════════════════════════════════════════════════════════════════════════

/// Node liveness failure slash: 0.5% (50 basis points)
/// Triggered when node offline ≥ NODE_LIVENESS_THRESHOLD_SECONDS
pub const NODE_LIVENESS_SLASH_PERCENT: u16 = 50;

/// Node data corruption slash: 5% (500 basis points)
/// Triggered on 2 consecutive data corruption events
pub const NODE_DATA_CORRUPTION_SLASH_PERCENT: u16 = 500;

/// Validator double-sign slash: 10% (1000 basis points)
/// Triggered when validator signs conflicting blocks at same height
pub const VALIDATOR_DOUBLE_SIGN_SLASH_PERCENT: u16 = 1000;

/// Validator prolonged offline slash: 1% (100 basis points)
/// Triggered when validator offline exceeds threshold
pub const VALIDATOR_OFFLINE_SLASH_PERCENT: u16 = 100;

/// Validator malicious block slash: 20% (2000 basis points)
/// Triggered when validator produces invalid/malicious block
pub const VALIDATOR_MALICIOUS_BLOCK_SLASH_PERCENT: u16 = 2000;

/// Node liveness threshold: 12 hours (43,200 seconds)
/// Node must send heartbeat within this interval
pub const NODE_LIVENESS_THRESHOLD_SECONDS: u64 = 43_200;

/// Force unbond delay: 30 days (2,592,000 seconds)
/// Duration of forced unbonding for repeated malicious behavior
pub const FORCE_UNBOND_DELAY_SECONDS: u64 = 2_592_000;

/// Slashing allocation to treasury: 50%
/// Portion of slashed tokens sent to protocol treasury
pub const SLASHING_TREASURY_RATIO: u8 = 50;

/// Slashing allocation to burn: 50%
/// Portion of slashed tokens permanently destroyed
pub const SLASHING_BURN_RATIO: u8 = 50;

// ════════════════════════════════════════════════════════════════════════════
// 13.14.1 — SLASHING REASON ENUM
// ════════════════════════════════════════════════════════════════════════════

/// Reason for automatic slashing (non-governance)
/// 
/// Variant order is consensus-critical. Do NOT reorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashingReason {
    /// Node offline ≥ 12 jam
    NodeLivenessFailure,
    /// Data corruption 2x berturut
    NodeDataCorruption,
    /// Repeated malicious behavior
    NodeMaliciousBehavior,
    /// Double signing
    ValidatorDoubleSign,
    /// Validator offline
    ValidatorProlongedOffline,
    /// Malicious block production
    ValidatorMaliciousBlock,
}

// ════════════════════════════════════════════════════════════════════════════
// 13.14.1 — NODE LIVENESS RECORD
// ════════════════════════════════════════════════════════════════════════════

/// Liveness tracking record for storage/compute nodes AND validators
/// 
/// Tracks node/validator availability and violation history for automatic slashing.
/// Field order is consensus-critical. Do NOT reorder.
///
/// ## 13.14.3 — Validator Detection Fields
///
/// Fields `double_sign_detected`, `malicious_block_detected`, dan `offline_since`
/// digunakan untuk deteksi pelanggaran validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeLivenessRecord {
    /// Address of the node being tracked
    pub node_address: Address,
    /// Unix timestamp of last heartbeat received
    pub last_seen_timestamp: u64,
    /// Count of consecutive liveness failures
    pub consecutive_failures: u32,
    /// Count of data corruption events (slash on 2)
    pub data_corruption_count: u32,
    /// Count of malicious behavior incidents
    pub malicious_behavior_count: u32,
    /// Unix timestamp until which node is force-unbonded (None = not force-unbonded)
    pub force_unbond_until: Option<u64>,
    /// Whether this node has been slashed
    pub slashed: bool,
    // ════════════════════════════════════════════════════════════════════════
    // 13.14.3 — VALIDATOR DETECTION FIELDS
    // ════════════════════════════════════════════════════════════════════════
    /// Whether double-sign has been detected for this validator
    pub double_sign_detected: bool,
    /// Whether malicious block production has been detected for this validator
    pub malicious_block_detected: bool,
    /// Unix timestamp when validator went offline (None = online or not tracked)
    pub offline_since: Option<u64>,
}
// ════════════════════════════════════════════════════════════════════════════
// 13.14.1 — SLASHING EVENT
// ════════════════════════════════════════════════════════════════════════════

/// Record of a slashing event for audit trail
/// 
/// Captures all details of an automatic slash execution.
/// This struct is for runtime tracking only (not persisted to LMDB).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingEvent {
    /// Address of slashed entity (node or validator)
    pub target: Address,
    /// Reason for the slash
    pub reason: SlashingReason,
    /// Total amount slashed from stake
    pub amount_slashed: u128,
    /// Amount transferred to treasury
    pub amount_to_treasury: u128,
    /// Amount permanently burned
    pub amount_burned: u128,
    /// Unix timestamp when slash occurred
    pub timestamp: u64,
}

// ════════════════════════════════════════════════════════════════════════════
// LEGACY VALIDATOR LIVENESS RECORD (13.7.K)
// ════════════════════════════════════════════════════════════════════════════

/// Liveness tracking record for a validator
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LivenessRecord {
    /// Number of consecutive blocks missed
    pub missed_blocks: u64,
    /// Whether this validator has been slashed
    pub slashed: bool,
    /// Total times slashed (for repeat offenders)
    pub slash_count: u64,
    /// Last block height where validator was active
    pub last_active_height: u64,
}

impl LivenessRecord {
    pub fn new() -> Self {
        Self {
            missed_blocks: 0,
            slashed: false,
            slash_count: 0,
            last_active_height: 0,
        }
    }

    /// Reset missed blocks counter (called when validator produces a block)
    pub fn reset_missed(&mut self, current_height: u64) {
        self.missed_blocks = 0;
        self.last_active_height = current_height;
    }

    /// Increment missed blocks counter
    pub fn increment_missed(&mut self) {
        self.missed_blocks = self.missed_blocks.saturating_add(1);
    }

    /// Check if validator should be slashed
    pub fn should_slash(&self) -> bool {
        !self.slashed && self.missed_blocks >= MAX_MISSED_BLOCKS
    }
}

/// Update liveness record for a validator
///
/// # Arguments
/// * `validator` - Address of the validator
/// * `produced_block` - Whether this validator produced the current block
/// * `current_height` - Current block height
/// * `state` - Mutable reference to chain state
///
/// # Returns
/// * `Option<String>` - Event string if slashing occurred
pub fn update_liveness(
    validator: &Address,
    produced_block: bool,
    current_height: u64,
    state: &mut ChainState,
) -> Option<String> {
    // Get or create liveness record
    let record = state.liveness_records
        .entry(*validator)
        .or_insert_with(LivenessRecord::new);

    if produced_block {
        // Validator produced a block - reset missed counter
        record.reset_missed(current_height);
        println!("✅ Validator {} produced block at height {}", validator, current_height);
        None
    } else {
        // Validator missed this block
        record.increment_missed();
        println!("⚠️  Validator {} missed block (consecutive: {})", 
                 validator, record.missed_blocks);

        // Check if slashing threshold reached
        if record.should_slash() {
            Some(apply_slashing(validator, state))
        } else {
            None
        }
    }
}

/// Apply slashing to a validator (13.8.J - Full Implementation)
///
/// This function:
/// - Marks validator as slashed
/// - Increments slash count
/// - Sets validator inactive in ValidatorSet
/// - Deducts SLASH_PERCENTAGE from validator stake
/// - Deducts SLASH_PERCENTAGE from all delegator stakes (proportional)
/// - Updates all QV weights
/// - Slashes pending unstake entries
/// - Transfers slashed amount to treasury
/// - Returns event string
pub fn apply_slashing(validator: &Address, state: &mut ChainState) -> String {
    println!("🔪 SLASHING VALIDATOR: {}", validator);
    println!("   Reason: Exceeded {} consecutive missed blocks", MAX_MISSED_BLOCKS);
    println!("   Slash percentage: {}%", SLASH_PERCENTAGE);

    // Update liveness record
    if let Some(record) = state.liveness_records.get_mut(validator) {
        record.slashed = true;
        record.slash_count = record.slash_count.saturating_add(1);
    }

    // Set validator inactive in ValidatorSet
    state.validator_set.set_active(validator, false);

    // Also update legacy validators map
    if let Some(v) = state.validators.get_mut(validator) {
        v.active = false;
    }

    // ============================================================
    // 13.8.J: Apply actual stake slashing
    // ============================================================
    
    // Apply full slash to validator and all delegators
    // This handles:
    // - Validator stake reduction
    // - Delegator stake reduction (proportional)
    // - QV weight updates
    // - Pending unstake slashing
    // - Treasury transfer
    let (validator_slashed, delegators_slashed, total_slashed) = 
        state.apply_full_slash(validator, SLASH_PERCENTAGE);

    let slash_count = state.liveness_records
        .get(validator)
        .map(|r| r.slash_count)
        .unwrap_or(0);

    let event = format!(
        "ValidatorSlashed:addr={},missed={},slash_count={},validator_slash={},delegator_slash={},total_slash={},to_treasury={}",
        validator, 
        MAX_MISSED_BLOCKS, 
        slash_count,
        validator_slashed,
        delegators_slashed,
        total_slashed,
        total_slashed
    );

    println!("   Event: {}", event);
    event
}

/// Update liveness for ALL active validators in a block
///
/// Called at the end of each block to:
/// - Reset counter for the proposer
/// - Increment counter for all other active validators
///
/// # Arguments
/// * `proposer` - Address of block proposer
/// * `current_height` - Current block height
/// * `state` - Mutable reference to chain state
///
/// # Returns
/// * `Vec<String>` - List of slashing events (if any)
pub fn update_all_validators_liveness(
    proposer: &Address,
    current_height: u64,
    state: &mut ChainState,
) -> Vec<String> {
    let mut events = Vec::new();

    // Get all active validators
    let active_validators: Vec<Address> = state.validator_set.validators
        .iter()
        .filter(|(_, v)| v.active)
        .map(|(addr, _)| *addr)
        .collect();

    if active_validators.is_empty() {
        return events;
    }

    println!("📊 Updating liveness for {} active validator(s) at height {}", 
             active_validators.len(), current_height);

    // Update each validator
    for validator in active_validators {
        let produced_block = &validator == proposer;
        if let Some(event) = update_liveness(&validator, produced_block, current_height, state) {
            events.push(event);
        }
    }

    events
}

/// Check if a validator is currently slashed
pub fn is_slashed(validator: &Address, state: &ChainState) -> bool {
    state.liveness_records
        .get(validator)
        .map(|r| r.slashed)
        .unwrap_or(false)
}

/// Get liveness status for a validator
pub fn get_liveness_status(validator: &Address, state: &ChainState) -> Option<LivenessRecord> {
    state.liveness_records.get(validator).cloned()
}

/// Reset slashing status (for governance/admin use)
/// This is a skeleton - full implementation would require governance vote
#[allow(dead_code)]
pub fn reset_slashing(validator: &Address, state: &mut ChainState) -> bool {
    if let Some(record) = state.liveness_records.get_mut(validator) {
        record.slashed = false;
        record.missed_blocks = 0;
        
        // Reactivate validator
        state.validator_set.set_active(validator, true);
        if let Some(v) = state.validators.get_mut(validator) {
            v.active = true;
        }
        
        println!("🔓 Validator {} slashing status reset", validator);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_liveness_record_new() {
        let record = LivenessRecord::new();
        assert_eq!(record.missed_blocks, 0);
        assert!(!record.slashed);
        assert_eq!(record.slash_count, 0);
    }

    #[test]
    fn test_should_slash() {
        let mut record = LivenessRecord::new();
        
        // Below threshold
        record.missed_blocks = MAX_MISSED_BLOCKS - 1;
        assert!(!record.should_slash());
        
        // At threshold
        record.missed_blocks = MAX_MISSED_BLOCKS;
        assert!(record.should_slash());
        
        // Already slashed
        record.slashed = true;
        assert!(!record.should_slash());
    }

    #[test]
    fn test_reset_missed() {
        let mut record = LivenessRecord::new();
        record.missed_blocks = 25;
        record.reset_missed(100);
        
        assert_eq!(record.missed_blocks, 0);
        assert_eq!(record.last_active_height, 100);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // 13.14.9 — COMPREHENSIVE SLASHING UNIT TESTS
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: Verify all slashing constants are exactly as specified.
    /// Assertion: All 9 constants match specification values.
    #[test]
    fn test_slashing_constants() {
        // Node slashing percentages (basis points)
        assert_eq!(NODE_LIVENESS_SLASH_PERCENT, 50, 
            "Node liveness slash should be 0.5% (50 bp)");
        assert_eq!(NODE_DATA_CORRUPTION_SLASH_PERCENT, 500, 
            "Node data corruption slash should be 5% (500 bp)");
        
        // Validator slashing percentages (basis points)
        assert_eq!(VALIDATOR_DOUBLE_SIGN_SLASH_PERCENT, 1000, 
            "Validator double-sign slash should be 10% (1000 bp)");
        assert_eq!(VALIDATOR_OFFLINE_SLASH_PERCENT, 100, 
            "Validator offline slash should be 1% (100 bp)");
        assert_eq!(VALIDATOR_MALICIOUS_BLOCK_SLASH_PERCENT, 2000, 
            "Validator malicious block slash should be 20% (2000 bp)");
        
        // Time thresholds
        assert_eq!(NODE_LIVENESS_THRESHOLD_SECONDS, 43_200, 
            "Node liveness threshold should be 12 hours (43200 seconds)");
        assert_eq!(FORCE_UNBOND_DELAY_SECONDS, 2_592_000, 
            "Force unbond delay should be 30 days (2592000 seconds)");
        
        // Allocation ratios (must sum to 100)
        assert_eq!(SLASHING_TREASURY_RATIO, 50, "Treasury ratio should be 50%");
        assert_eq!(SLASHING_BURN_RATIO, 50, "Burn ratio should be 50%");
        assert_eq!(
            SLASHING_TREASURY_RATIO + SLASHING_BURN_RATIO, 
            100, 
            "Treasury + Burn must equal 100%"
        );
    }

    /// Test: Verify NodeLivenessRecord default values.
    /// Assertion: All counters are 0, all flags are false, all Options are None.
    #[test]
    fn test_node_liveness_record_default() {
        let addr = Address::from_bytes([0x01; 20]);
        let record = NodeLivenessRecord {
            node_address: addr,
            last_seen_timestamp: 0,
            consecutive_failures: 0,
            data_corruption_count: 0,
            malicious_behavior_count: 0,
            force_unbond_until: None,
            slashed: false,
            double_sign_detected: false,
            malicious_block_detected: false,
            offline_since: None,
        };
        
        // Verify counters are zero
        assert_eq!(record.last_seen_timestamp, 0, "last_seen_timestamp should be 0");
        assert_eq!(record.consecutive_failures, 0, "consecutive_failures should be 0");
        assert_eq!(record.data_corruption_count, 0, "data_corruption_count should be 0");
        assert_eq!(record.malicious_behavior_count, 0, "malicious_behavior_count should be 0");
        
        // Verify flags are false
        assert!(!record.slashed, "slashed should be false");
        assert!(!record.double_sign_detected, "double_sign_detected should be false");
        assert!(!record.malicious_block_detected, "malicious_block_detected should be false");
        
        // Verify Options are None
        assert!(record.force_unbond_until.is_none(), "force_unbond_until should be None");
        assert!(record.offline_since.is_none(), "offline_since should be None");
        
        // Verify address is correct
        assert_eq!(record.node_address, addr, "node_address should match");
    }

    /// Test: Verify all SlashingReason enum variants exist and can be instantiated.
    /// Assertion: All 6 variants are available and distinguishable.
    #[test]
    fn test_slashing_reason_variants() {
        // Instantiate all variants
        let reason1 = SlashingReason::NodeLivenessFailure;
        let reason2 = SlashingReason::NodeDataCorruption;
        let reason3 = SlashingReason::NodeMaliciousBehavior;
        let reason4 = SlashingReason::ValidatorDoubleSign;
        let reason5 = SlashingReason::ValidatorProlongedOffline;
        let reason6 = SlashingReason::ValidatorMaliciousBlock;
        
        // Verify each variant is unique
        assert_ne!(reason1, reason2, "NodeLivenessFailure != NodeDataCorruption");
        assert_ne!(reason2, reason3, "NodeDataCorruption != NodeMaliciousBehavior");
        assert_ne!(reason3, reason4, "NodeMaliciousBehavior != ValidatorDoubleSign");
        assert_ne!(reason4, reason5, "ValidatorDoubleSign != ValidatorProlongedOffline");
        assert_ne!(reason5, reason6, "ValidatorProlongedOffline != ValidatorMaliciousBlock");
        
        // Verify equality for same variants
        assert_eq!(reason1, SlashingReason::NodeLivenessFailure);
        assert_eq!(reason4, SlashingReason::ValidatorDoubleSign);
        
        // Verify Debug trait works (no panic)
        let _debug1 = format!("{:?}", reason1);
        let _debug6 = format!("{:?}", reason6);
        
        // Verify Clone trait works
        let cloned = reason1.clone();
        assert_eq!(cloned, reason1);
        
        // Verify Copy trait works
        let copied: SlashingReason = reason4;
        assert_eq!(copied, reason4);
    }

    /// Test: SlashingEvent can be created correctly.
    /// Assertion: All fields are correctly stored.
    #[test]
    fn test_slashing_event_creation() {
        let target = Address::from_bytes([0xAA; 20]);
        let event = SlashingEvent {
            target,
            reason: SlashingReason::ValidatorDoubleSign,
            amount_slashed: 1_000_000,
            amount_to_treasury: 500_000,
            amount_burned: 500_000,
            timestamp: 1700000000,
        };
        
        assert_eq!(event.target, target);
        assert_eq!(event.reason, SlashingReason::ValidatorDoubleSign);
        assert_eq!(event.amount_slashed, 1_000_000);
        assert_eq!(event.amount_to_treasury, 500_000);
        assert_eq!(event.amount_burned, 500_000);
        assert_eq!(event.timestamp, 1700000000);
        
        // Verify allocation adds up
        assert_eq!(
            event.amount_to_treasury + event.amount_burned, 
            event.amount_slashed,
            "Treasury + Burned should equal total slashed"
        );
    }

    /// Test: Verify slash percentage calculations.
    /// Assertion: Basis points correctly convert to amounts.
    #[test]
    fn test_slashing_basis_points_calculation() {
        let stake = 10_000_000u128; // 10M stake
        
        // 0.5% (50 bp) = 50,000
        let node_liveness_slash = (stake * NODE_LIVENESS_SLASH_PERCENT as u128) / 10_000;
        assert_eq!(node_liveness_slash, 50_000, "0.5% of 10M should be 50K");
        
        // 5% (500 bp) = 500,000
        let data_corruption_slash = (stake * NODE_DATA_CORRUPTION_SLASH_PERCENT as u128) / 10_000;
        assert_eq!(data_corruption_slash, 500_000, "5% of 10M should be 500K");
        
        // 10% (1000 bp) = 1,000,000
        let double_sign_slash = (stake * VALIDATOR_DOUBLE_SIGN_SLASH_PERCENT as u128) / 10_000;
        assert_eq!(double_sign_slash, 1_000_000, "10% of 10M should be 1M");
        
        // 1% (100 bp) = 100,000
        let offline_slash = (stake * VALIDATOR_OFFLINE_SLASH_PERCENT as u128) / 10_000;
        assert_eq!(offline_slash, 100_000, "1% of 10M should be 100K");
        
        // 20% (2000 bp) = 2,000,000
        let malicious_slash = (stake * VALIDATOR_MALICIOUS_BLOCK_SLASH_PERCENT as u128) / 10_000;
        assert_eq!(malicious_slash, 2_000_000, "20% of 10M should be 2M");
    }

    /// Test: Severity ordering of slash percentages.
    /// Assertion: malicious > double_sign > corruption > offline > liveness
    #[test]
    fn test_slashing_severity_ordering() {
        assert!(
            VALIDATOR_MALICIOUS_BLOCK_SLASH_PERCENT > VALIDATOR_DOUBLE_SIGN_SLASH_PERCENT,
            "Malicious block should be more severe than double-sign"
        );
        assert!(
            VALIDATOR_DOUBLE_SIGN_SLASH_PERCENT > NODE_DATA_CORRUPTION_SLASH_PERCENT,
            "Double-sign should be more severe than data corruption"
        );
        assert!(
            NODE_DATA_CORRUPTION_SLASH_PERCENT > VALIDATOR_OFFLINE_SLASH_PERCENT,
            "Data corruption should be more severe than offline"
        );
        assert!(
            VALIDATOR_OFFLINE_SLASH_PERCENT > NODE_LIVENESS_SLASH_PERCENT,
            "Validator offline should be more severe than node liveness"
        );
    }
}