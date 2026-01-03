//! Internal miscellaneous helper functions
//! Dipindahkan dari state.rs untuk modularisasi

use crate::types::Address;
use crate::slashing::LivenessRecord;
use crate::epoch::{EpochInfo, EpochConfig};
use anyhow::Result;
use super::ChainState;

impl ChainState {
    /// Get treasury balance (13.7.G)
    pub fn get_treasury_balance(&self) -> u128 {
        self.treasury_balance
    }

    /// Get delegator pool balance (13.7.H)
    pub fn get_delegator_pool(&self) -> u128 {
        self.delegator_pool
    }

    /// Get liveness record for a validator (13.7.K)
    pub fn get_liveness_record(&self, addr: &Address) -> Option<&LivenessRecord> {
        self.liveness_records.get(addr)
    }

    pub fn is_validator_slashed(&self, addr: &Address) -> bool {
        self.liveness_records
            .get(addr)
            .map(|r| r.slashed)
            .unwrap_or(false)
    }

    /// Get current epoch number (13.7.L)
    pub fn get_current_epoch(&self) -> u64 {
        self.epoch_info.epoch_number
    }

    /// Get epoch info (13.7.L)
    pub fn get_epoch_info(&self) -> &EpochInfo {
        &self.epoch_info
    }

    /// Set epoch config (13.7.L)
    pub fn set_epoch_config(&mut self, config: EpochConfig) {
        self.epoch_config = config;
    }

    /// Check and apply epoch rotation if needed (13.7.L)
    /// Returns events if rotation occurred
    pub fn maybe_rotate_epoch(&mut self, height: u64) -> Result<Vec<String>> {
        crate::epoch::maybe_rotate_epoch(self, height, &self.epoch_config.clone())
    }
}
