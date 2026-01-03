//! Internal fee pool management functions
//! Dipindahkan dari state.rs untuk modularisasi

use crate::types::Address;
use anyhow::Result;
use super::ChainState;

impl ChainState {
    /// Get validator fee pool balance
    pub fn get_validator_fee_pool(&self) -> u128 {
        self.validator_fee_pool
    }

    /// Add to validator fee pool
    pub fn add_to_validator_fee_pool(&mut self, amount: u128) {
        self.validator_fee_pool = self.validator_fee_pool.saturating_add(amount);
    }

    /// Claim from validator fee pool
    pub fn claim_validator_fee(&mut self, validator: &Address, amount: u128) -> Result<()> {
        if self.validator_fee_pool < amount {
            anyhow::bail!("insufficient validator fee pool");
        }
        
        self.validator_fee_pool -= amount;
        let balance = self.balances.entry(*validator).or_insert(0);
        *balance = balance.saturating_add(amount);
        
        Ok(())
    }

    // ============================================================
    // FEE POOL MANAGEMENT (13.8.E)
    // ============================================================

    /// Get storage fee pool balance
    pub fn get_storage_fee_pool(&self) -> u128 {
        self.storage_fee_pool
    }

    /// Get compute fee pool balance
    pub fn get_compute_fee_pool(&self) -> u128 {
        self.compute_fee_pool
    }

    /// Add fee to appropriate pool based on ResourceClass (13.8.E + 13.9 Blueprint)
    /// 
    /// Fee Distribution (Blueprint 70/20/10):
    /// - Storage/Compute: Node 70%, Validator 20%, Treasury 10%
    /// - Transfer/Governance: Validator 100%
    /// - Anti-self-dealing node: jika service_node == sender → node_share ke treasury
    /// 
    /// This is a thin wrapper that applies the same allocation rules as apply_payload.
    /// FeeSplit is calculated via crate::tokenomics::calculate_fee_by_resource_class.
    pub fn allocate_fee_to_pool(
        &mut self,
        resource_class: &crate::tx::ResourceClass,
        fee: u128,
        service_node: Option<Address>,
        _miner_addr: &Address,
        sender: &Address,
    ) {
        use crate::tx::ResourceClass;
        use crate::tokenomics::calculate_fee_by_resource_class;
        
        let split = calculate_fee_by_resource_class(fee, resource_class, service_node, sender);
        
        match resource_class {
            ResourceClass::Transfer => {
                // 100% to validator (proposer)
                self.validator_fee_pool += split.validator_share;
                println!("💰 Transfer Fee: {} → validator_fee_pool", split.validator_share);
            }
            ResourceClass::Governance => {
                // Blueprint: 100% validator
                self.validator_fee_pool += split.validator_share;
                self.treasury_balance += split.treasury_share;
                println!("💰 Governance Fee: {} → validator({}), treasury({})", 
                         fee, split.validator_share, split.treasury_share);
            }
            ResourceClass::Storage => {
                // Blueprint 70/20/10 (anti-self-dealing sudah dihandle di calculate_fee_by_resource_class)
                if let Some(node) = service_node {
                    if split.node_share > 0 {
                        *self.balances.entry(node).or_insert(0) += split.node_share;
                        *self.node_earnings.entry(node).or_insert(0) += split.node_share;
                        println!("💾 Storage Fee: node_share={} → storage_node {}", split.node_share, node);
                    }
                } else {
                    self.storage_fee_pool += split.node_share;
                    println!("💾 Storage Fee: {} → storage_fee_pool", split.node_share);
                }
                self.validator_fee_pool += split.validator_share;
                self.treasury_balance += split.treasury_share;
                println!("   validator_share={}, treasury_share={}", split.validator_share, split.treasury_share);
            }
            ResourceClass::Compute => {
                // Blueprint 70/20/10 (anti-self-dealing sudah dihandle di calculate_fee_by_resource_class)
                if let Some(node) = service_node {
                    if split.node_share > 0 {
                        *self.balances.entry(node).or_insert(0) += split.node_share;
                        *self.node_earnings.entry(node).or_insert(0) += split.node_share;
                        println!("🖥️ Compute Fee: node_share={} → compute_node {}", split.node_share, node);
                    }
                } else {
                    self.compute_fee_pool += split.node_share;
                    println!("🖥️ Compute Fee: {} → compute_fee_pool", split.node_share);
                }
                self.validator_fee_pool += split.validator_share;
                self.treasury_balance += split.treasury_share;
                println!("   validator_share={}, treasury_share={}", split.validator_share, split.treasury_share);
            }
        }
    }

    /// Thin wrapper to apply FeeSplit directly (13.9)
    /// Used for cases where FeeSplit is already calculated.
    /// Applies identical allocation rules as apply_payload.
    pub fn apply_fee_split(
        &mut self,
        fee_split: &crate::tokenomics::FeeSplit,
        resource_class: &crate::tx::ResourceClass,
        service_node: Option<Address>,
    ) {
        use crate::tx::ResourceClass;
        
        match resource_class {
            ResourceClass::Transfer | ResourceClass::Governance => {
                self.validator_fee_pool += fee_split.validator_share;
                self.treasury_balance += fee_split.treasury_share;
            }
            ResourceClass::Storage => {
                if let Some(node) = service_node {
                    if fee_split.node_share > 0 {
                        *self.balances.entry(node).or_insert(0) += fee_split.node_share;
                        *self.node_earnings.entry(node).or_insert(0) += fee_split.node_share;
                    }
                } else {
                    self.storage_fee_pool += fee_split.node_share;
                }
                self.validator_fee_pool += fee_split.validator_share;
                self.treasury_balance += fee_split.treasury_share;
            }
            ResourceClass::Compute => {
                if let Some(node) = service_node {
                    if fee_split.node_share > 0 {
                        *self.balances.entry(node).or_insert(0) += fee_split.node_share;
                        *self.node_earnings.entry(node).or_insert(0) += fee_split.node_share;
                    }
                } else {
                    self.compute_fee_pool += fee_split.node_share;
                }
                self.validator_fee_pool += fee_split.validator_share;
                self.treasury_balance += fee_split.treasury_share;
            }
        }
    }

    /// Claim from storage fee pool (for storage nodes)
    pub fn claim_storage_fee(&mut self, node: &Address, amount: u128) -> Result<()> {
        if self.storage_fee_pool < amount {
            anyhow::bail!("insufficient storage fee pool");
        }
        self.storage_fee_pool -= amount;
        *self.balances.entry(*node).or_insert(0) += amount;
        Ok(())
    }

    /// Claim from compute fee pool (for compute nodes)
    pub fn claim_compute_fee(&mut self, node: &Address, amount: u128) -> Result<()> {
        if self.compute_fee_pool < amount {
            anyhow::bail!("insufficient compute fee pool");
        }
        self.compute_fee_pool -= amount;
        *self.balances.entry(*node).or_insert(0) += amount;
        Ok(())
    }
}