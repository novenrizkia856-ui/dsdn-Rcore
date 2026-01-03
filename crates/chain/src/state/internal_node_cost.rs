//! Node cost index & per-node earnings accounting (13.9)
//!
//! Module ini mengelola:
//! - Node cost index multiplier per node
//! - Per-node earnings tracking
//!
//! **CONSENSUS-CRITICAL**: Field node_cost_index dan node_earnings
//! termasuk dalam state_root computation.

use crate::types::Address;
use super::ChainState;
use super::internal_gas::DEFAULT_NODE_COST_INDEX;

impl ChainState {
    // ════════════════════════════════════════════════════════════════════════════
    // NODE COST INDEX MANAGEMENT
    // ════════════════════════════════════════════════════════════════════════════

    /// Set node cost index multiplier for a node
    ///
    /// # Arguments
    /// * `addr` - Node address
    /// * `multiplier` - Cost index multiplier (basis 100 = 1.0x)
    ///
    /// # Note
    /// Nilai 100 = 1.0x multiplier (default)
    /// Nilai 150 = 1.5x multiplier (premium node)
    /// Nilai 50 = 0.5x multiplier (discounted node)
    pub fn set_node_cost_index(&mut self, addr: Address, multiplier: u128) {
        self.node_cost_index.insert(addr, multiplier);
    }

    /// Get node cost index multiplier for a node
    ///
    /// # Returns
    /// Cost index multiplier (basis 100), or DEFAULT_NODE_COST_INDEX if not set
    pub fn get_node_cost_index(&self, addr: &Address) -> u128 {
        self.node_cost_index
            .get(addr)
            .copied()
            .unwrap_or(DEFAULT_NODE_COST_INDEX)
    }

    /// List all node cost indexes
    ///
    /// # Returns
    /// Vec of (address, multiplier) tuples, sorted by address for determinism
    pub fn list_node_cost_indexes(&self) -> Vec<(Address, u128)> {
        let mut result: Vec<(Address, u128)> = self.node_cost_index
            .iter()
            .map(|(addr, multiplier)| (*addr, *multiplier))
            .collect();
        result.sort_by_key(|(addr, _)| *addr);
        result
    }

    /// Remove node cost index multiplier for a node
    ///
    /// # Arguments
    /// * `addr` - Node address to remove
    ///
    /// # Returns
    /// Previous multiplier value if existed, None otherwise
    ///
    /// # Note
    /// Setelah removal, node akan menggunakan DEFAULT_NODE_COST_INDEX (100).
    /// Perubahan node_cost_index adalah consensus-critical dan termasuk dalam state_root.
    /// Method ini dipanggil via Governance action atau Admin CLI.
    pub fn remove_node_cost_index(&mut self, addr: &Address) -> Option<u128> {
        self.node_cost_index.remove(addr)
    }
    // ════════════════════════════════════════════════════════════════════════════
    // NODE EARNINGS MANAGEMENT
    // ════════════════════════════════════════════════════════════════════════════

    /// Credit earnings to a node
    ///
    /// # Arguments
    /// * `addr` - Node address
    /// * `amount` - Amount to credit
    ///
    /// # Note
    /// Earnings di-accumulate dan dapat di-claim via claim_node_earning()
    pub fn credit_node_earning(&mut self, addr: Address, amount: u128) {
        let current = self.node_earnings.get(&addr).copied().unwrap_or(0);
        self.node_earnings.insert(addr, current.saturating_add(amount));
    }

    /// Claim all accumulated earnings for a node
    ///
    /// # Returns
    /// Total earnings claimed (resets node earnings to 0)
    ///
    /// # Note
    /// Caller bertanggung jawab untuk mentransfer amount ke balance node
    pub fn claim_node_earning(&mut self, addr: Address) -> u128 {
        let earnings = self.node_earnings.remove(&addr).unwrap_or(0);
        earnings
    }
}