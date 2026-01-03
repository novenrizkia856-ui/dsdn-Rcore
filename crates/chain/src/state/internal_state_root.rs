//! Internal state root computation
//! Dipindahkan dari state.rs untuk modularisasi

use crate::types::Hash;
use crate::crypto::sha3_512_bytes;
use anyhow::Result;
use super::ChainState;

impl ChainState {
    /// Compute state_root: Simple Merkle over serialized world state (balances + nonces + locked + validators)
    /// For production, use a proper Merkle Patricia Trie; here simplified concatenation + hash
    pub fn compute_state_root(&self) -> Result<Hash> {
        let mut accum = Vec::new();

        // Serialize and sort balances
        let mut bal_vec: Vec<(&crate::types::Address, &u128)> = self.balances.iter().collect();
        bal_vec.sort_by_key(|&(addr, _)| addr);
        for (addr, bal) in bal_vec {
            accum.extend_from_slice(addr.as_bytes());
            accum.extend_from_slice(&bal.to_be_bytes());
        }

        // Nonces
        let mut nonce_vec: Vec<(&crate::types::Address, &u64)> = self.nonces.iter().collect();
        nonce_vec.sort_by_key(|&(addr, _)| addr);
        for (addr, nonce) in nonce_vec {
            accum.extend_from_slice(addr.as_bytes());
            accum.extend_from_slice(&nonce.to_be_bytes());
        }

        // Locked
        let mut locked_vec: Vec<(&crate::types::Address, &u128)> = self.locked.iter().collect();
        locked_vec.sort_by_key(|&(addr, _)| addr);
        for (addr, locked) in locked_vec {
            accum.extend_from_slice(addr.as_bytes());
            accum.extend_from_slice(&locked.to_be_bytes());
        }

        let mut val_vec: Vec<(&crate::types::Address, &super::Validator)> = self.validators.iter().collect();
        val_vec.sort_by_key(|&(addr, _)| addr);
        for (addr, val) in val_vec {
            accum.extend_from_slice(addr.as_bytes());
            accum.extend_from_slice(&val.stake.to_be_bytes());
            accum.extend_from_slice(&val.pubkey);
            accum.extend_from_slice(&self.reward_pool.to_be_bytes());
            accum.push(if val.active { 1u8 } else { 0u8 });
        }

        // ValidatorSet (DPoS Hybrid) — include dalam state root
        let mut vset_vec: Vec<(&crate::types::Address, &super::ValidatorInfo)> = self.validator_set.validators.iter().collect();
        vset_vec.sort_by_key(|&(addr, _)| addr);
        for (addr, vinfo) in vset_vec {
            accum.extend_from_slice(addr.as_bytes());
            accum.extend_from_slice(&vinfo.stake.to_be_bytes());
            accum.extend_from_slice(&vinfo.pubkey);
            accum.push(if vinfo.active { 1u8 } else { 0u8 });
            if let Some(ref m) = vinfo.moniker {
                accum.extend_from_slice(m.as_bytes());
            }
        }

        // Delegations — include dalam state root untuk QV integrity
        let mut del_vec: Vec<&crate::types::Address> = self.delegations.keys().collect();
        del_vec.sort();
        for validator_addr in del_vec {
            accum.extend_from_slice(validator_addr.as_bytes());
            if let Some(delegators) = self.delegations.get(validator_addr) {
                let mut delegator_vec: Vec<(&crate::types::Address, &u128)> = delegators.iter().collect();
                delegator_vec.sort_by_key(|&(addr, _)| addr);
                for (del_addr, amount) in delegator_vec {
                    accum.extend_from_slice(del_addr.as_bytes());
                    accum.extend_from_slice(&amount.to_be_bytes());
                }
            }
        }

        // Delegator pool 
        accum.extend_from_slice(&self.delegator_pool.to_be_bytes());

        // Validator stakes (13.8.A)
        let mut vstake_vec: Vec<(&crate::types::Address, &u128)> = self.validator_stakes.iter().collect();
        vstake_vec.sort_by_key(|&(addr, _)| addr);
        for (addr, stake) in vstake_vec {
            accum.extend_from_slice(addr.as_bytes());
            accum.extend_from_slice(&stake.to_be_bytes());
        }

        // Delegator stakes (13.8.A)
        let mut dstake_vec: Vec<(&crate::types::Address, &u128)> = self.delegator_stakes.iter().collect();
        dstake_vec.sort_by_key(|&(addr, _)| addr);
        for (addr, stake) in dstake_vec {
            accum.extend_from_slice(addr.as_bytes());
            accum.extend_from_slice(&stake.to_be_bytes());
        }

        // Delegator to validator mapping (13.8.B)
        let mut d2v_vec: Vec<(&crate::types::Address, &crate::types::Address)> = self.delegator_to_validator.iter().collect();
        d2v_vec.sort_by_key(|&(addr, _)| addr);
        for (delegator, validator) in d2v_vec {
            accum.extend_from_slice(delegator.as_bytes());
            accum.extend_from_slice(validator.as_bytes());
        }

        // Validator fee pool (13.8.A)
        accum.extend_from_slice(&self.validator_fee_pool.to_be_bytes());

        // Storage fee pool (13.8.E)
        accum.extend_from_slice(&self.storage_fee_pool.to_be_bytes());

        // Compute fee pool (13.8.E)
        accum.extend_from_slice(&self.compute_fee_pool.to_be_bytes());

        // Pending delegator rewards (13.8.E)
        let mut pdr_vec: Vec<(&crate::types::Address, &u128)> = self.pending_delegator_rewards.iter().collect();
        pdr_vec.sort_by_key(|&(addr, _)| addr);
        for (addr, reward) in pdr_vec {
            accum.extend_from_slice(addr.as_bytes());
            accum.extend_from_slice(&reward.to_be_bytes());
        }

        // Delegator reward accrued (13.8.F)
        let mut dra_vec: Vec<(&crate::types::Address, &u128)> = self.delegator_reward_accrued.iter().collect();
        dra_vec.sort_by_key(|&(addr, _)| addr);
        for (addr, accrued) in dra_vec {
            accum.extend_from_slice(addr.as_bytes());
            accum.extend_from_slice(&accrued.to_be_bytes());
        }

        // Delegator last epoch (13.8.F)
        let mut dle_vec: Vec<(&crate::types::Address, &u64)> = self.delegator_last_epoch.iter().collect();
        dle_vec.sort_by_key(|&(addr, _)| addr);
        for (addr, epoch) in dle_vec {
            accum.extend_from_slice(addr.as_bytes());
            accum.extend_from_slice(&epoch.to_be_bytes());
        }

        // Year start epoch (13.8.F)
        accum.extend_from_slice(&self.year_start_epoch.to_be_bytes());

        // Pending unstakes (13.8.G)
        let mut pu_vec: Vec<&crate::types::Address> = self.pending_unstakes.keys().collect();
        pu_vec.sort();
        for addr in pu_vec {
            accum.extend_from_slice(addr.as_bytes());
            if let Some(entries) = self.pending_unstakes.get(addr) {
                accum.extend_from_slice(&(entries.len() as u64).to_be_bytes());
                for entry in entries {
                    accum.extend_from_slice(&entry.amount.to_be_bytes());
                    accum.extend_from_slice(&entry.unlock_ts.to_be_bytes());
                    accum.extend_from_slice(entry.validator.as_bytes());
                    accum.push(if entry.is_validator_unstake { 1u8 } else { 0u8 });
                }
            }
        }

        // QV weights (13.8.C)
        let mut qv_vec: Vec<(&crate::types::Address, &u128)> = self.qv_weights.iter().collect();
        qv_vec.sort_by_key(|&(addr, _)| addr);
        for (addr, weight) in qv_vec {
            accum.extend_from_slice(addr.as_bytes());
            accum.extend_from_slice(&weight.to_be_bytes());
        }

        // Validator QV weights (13.8.C)
        let mut vqv_vec: Vec<(&crate::types::Address, &u128)> = self.validator_qv_weights.iter().collect();
        vqv_vec.sort_by_key(|&(addr, _)| addr);
        for (addr, weight) in vqv_vec {
            accum.extend_from_slice(addr.as_bytes());
            accum.extend_from_slice(&weight.to_be_bytes());
        }

        // Liveness records
        let mut liveness_vec: Vec<(&crate::types::Address, &crate::slashing::LivenessRecord)> = self.liveness_records.iter().collect();
        liveness_vec.sort_by_key(|&(addr, _)| addr);
        for (addr, record) in liveness_vec {
            accum.extend_from_slice(addr.as_bytes());
            accum.extend_from_slice(&record.missed_blocks.to_be_bytes());
            accum.push(if record.slashed { 1u8 } else { 0u8 });
            accum.extend_from_slice(&record.slash_count.to_be_bytes());
        }

        // Epoch info (13.7.L)
        accum.extend_from_slice(&self.epoch_info.epoch_number.to_be_bytes());
        accum.extend_from_slice(&self.epoch_info.start_height.to_be_bytes());
        accum.extend_from_slice(&(self.epoch_info.active_validators as u64).to_be_bytes());
        accum.extend_from_slice(&self.epoch_info.total_stake.to_be_bytes());

        // Node cost index (13.9) - consensus-critical
        let mut nci_vec: Vec<(&crate::types::Address, &u128)> = self.node_cost_index.iter().collect();
        nci_vec.sort_by_key(|&(addr, _)| addr);
        for (addr, cost_index) in nci_vec {
            accum.extend_from_slice(addr.as_bytes());
            accum.extend_from_slice(&cost_index.to_be_bytes());
        }

        // Node earnings (13.9) - consensus-critical
        let mut ne_vec: Vec<(&crate::types::Address, &u128)> = self.node_earnings.iter().collect();
        ne_vec.sort_by_key(|&(addr, _)| addr);
        for (addr, earnings) in ne_vec {
            accum.extend_from_slice(addr.as_bytes());
            accum.extend_from_slice(&earnings.to_be_bytes());
        }

// Claimed receipts (13.10) - consensus-critical
        // Position #25 in state_root ordering
        // Prevents receipt replay across forks
        let mut cr_vec: Vec<&Hash> = self.claimed_receipts.iter().collect();
        cr_vec.sort_by_key(|h| h.as_bytes());
        for receipt_id in cr_vec {
            accum.extend_from_slice(receipt_id.as_bytes());
        }

        // ════════════════════════════════════════════════════════════════════════════
        // GOVERNANCE STATE (13.12.6) — CONSENSUS-CRITICAL
        // ════════════════════════════════════════════════════════════════════════════
        // Ordering #26-#29 adalah FINAL. Perubahan memerlukan HARD FORK.
        // ════════════════════════════════════════════════════════════════════════════

        // #26 — proposals
        // Sort by proposal_id ascending
        // Format: [proposal_id (8 bytes BE)] + [bincode serialized Proposal]
        let mut proposals_vec: Vec<(&u64, &super::Proposal)> = self.proposals.iter().collect();
        proposals_vec.sort_by_key(|&(id, _)| *id);
        for (proposal_id, proposal) in proposals_vec {
            accum.extend_from_slice(&proposal_id.to_be_bytes());
            let proposal_bytes = bincode::serialize(proposal).expect("proposal serialization must not fail");
            accum.extend_from_slice(&proposal_bytes);
        }

        // #27 — proposal_votes
        // Sort by (proposal_id ASC, voter_address ASC)
        // Format: [proposal_id (8 bytes BE)] + [voter_address (20 bytes)] + [bincode serialized Vote]
        let mut votes_flat: Vec<(u64, &crate::types::Address, &super::Vote)> = Vec::new();
        for (proposal_id, voters_map) in self.proposal_votes.iter() {
            for (voter_addr, vote) in voters_map.iter() {
                votes_flat.push((*proposal_id, voter_addr, vote));
            }
        }
        votes_flat.sort_by(|a, b| {
            match a.0.cmp(&b.0) {
                std::cmp::Ordering::Equal => a.1.cmp(b.1),
                other => other,
            }
        });
        for (proposal_id, voter_addr, vote) in votes_flat {
            accum.extend_from_slice(&proposal_id.to_be_bytes());
            accum.extend_from_slice(voter_addr.as_bytes());
            let vote_bytes = bincode::serialize(vote).expect("vote serialization must not fail");
            accum.extend_from_slice(&vote_bytes);
        }

        // #28 — governance_config
        // Format: [bincode serialized governance_config]
        let config_bytes = bincode::serialize(&self.governance_config).expect("governance_config serialization must not fail");
        accum.extend_from_slice(&config_bytes);

// #29 — proposal_count
        // Format: [proposal_count as u64 (8 bytes BE)]
        accum.extend_from_slice(&self.proposal_count.to_be_bytes());

        // ════════════════════════════════════════════════════════════════════════════
        // NODE LIVENESS STATE (13.14.7) — CONSENSUS-CRITICAL
        // ════════════════════════════════════════════════════════════════════════════
        // Position #30 in state_root ordering
        // Format is CONSENSUS-CRITICAL. Changes require HARD FORK.
        // ════════════════════════════════════════════════════════════════════════════

        // #30 — node_liveness_records
        // Sort by node_address ascending
        // Format: [node_address (20 bytes)] + [bincode serialized NodeLivenessRecord]
        let mut nlr_vec: Vec<(&crate::types::Address, &crate::slashing::NodeLivenessRecord)> = 
            self.node_liveness_records.iter().collect();
        nlr_vec.sort_by_key(|&(addr, _)| addr);
        for (node_addr, record) in nlr_vec {
            accum.extend_from_slice(node_addr.as_bytes());
            let record_bytes = bincode::serialize(record).expect("NodeLivenessRecord serialization must not fail");
            accum.extend_from_slice(&record_bytes);
        }

        // ════════════════════════════════════════════════════════════════════════════
        // ECONOMIC STATE (13.15.7) — CONSENSUS-CRITICAL
        // ════════════════════════════════════════════════════════════════════════════
        // Position #31-#34 in state_root ordering
        // Format is CONSENSUS-CRITICAL. Changes require HARD FORK.
        // ════════════════════════════════════════════════════════════════════════════

        // #31 — deflation_config
        // Format: [bincode serialized DeflationConfig]
        let deflation_config_bytes = bincode::serialize(&self.deflation_config)
            .expect("DeflationConfig serialization must not fail");
        accum.extend_from_slice(&deflation_config_bytes);

        // #32 — economic_metrics
        // Format: [bincode serialized EconomicMetrics]
        let economic_metrics_bytes = bincode::serialize(&self.economic_metrics)
            .expect("EconomicMetrics serialization must not fail");
        accum.extend_from_slice(&economic_metrics_bytes);

        // #33 — last_burn_epoch
        // Format: [u64 big-endian bytes]
        accum.extend_from_slice(&self.last_burn_epoch.to_be_bytes());

        // #34 — cumulative_burned
        // Format: [u128 big-endian bytes]
        accum.extend_from_slice(&self.cumulative_burned.to_be_bytes());

        // ════════════════════════════════════════════════════════════════════════════
        // STORAGE CONTRACT STATE (13.17.7) — CONSENSUS-CRITICAL
        // ════════════════════════════════════════════════════════════════════════════
        // Position #35 in state_root ordering
        // Format is CONSENSUS-CRITICAL. Changes require HARD FORK.
        // ════════════════════════════════════════════════════════════════════════════

        // #35 — storage_contracts
        // Sort by contract_id ascending
        // Format: [contract_id (64 bytes)] + [bincode serialized StorageContract]
        let mut sc_vec: Vec<(&crate::types::Hash, &super::StorageContract)> = 
            self.storage_contracts.iter().collect();
        sc_vec.sort_by_key(|&(id, _)| id.as_bytes());
        for (contract_id, contract) in sc_vec {
            accum.extend_from_slice(contract_id.as_bytes());
            let contract_bytes = bincode::serialize(contract)
                .expect("StorageContract serialization must not fail");
            accum.extend_from_slice(&contract_bytes);
        }

        // Hash the accumulated bytes
        Ok(Hash::from_bytes(sha3_512_bytes(&accum)))
    }
}