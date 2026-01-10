//! Internal account management functions
//! Logic saja — BUKAN method ChainState

use crate::types::{Address, MAX_SUPPLY};
use anyhow::Result;
use super::ChainState;

pub fn create_account(state: &mut ChainState, addr: Address) {
    state.balances.entry(addr).or_insert(0u128);
    state.nonces.entry(addr).or_insert(0u64);
    state.locked.entry(addr).or_insert(0u128);
}

pub fn get_balance(state: &ChainState, addr: &Address) -> u128 {
    *state.balances.get(addr).unwrap_or(&0u128)
}

pub fn get_locked(state: &ChainState, addr: &Address) -> u128 {
    *state.locked.get(addr).unwrap_or(&0u128)
}

pub fn get_nonce(state: &ChainState, addr: &Address) -> u64 {
    *state.nonces.get(addr).unwrap_or(&0u64)
}

pub fn increment_nonce(state: &mut ChainState, addr: &Address) {
    let n = state.nonces.entry(*addr).or_insert(0u64);
    *n = n.saturating_add(1);
}

pub fn mint(state: &mut ChainState, addr: &Address, amount: u128) -> Result<()> {
    let new_supply = state.total_supply.checked_add(amount)
        .ok_or_else(|| anyhow::anyhow!("overflow on mint"))?;

    if new_supply > MAX_SUPPLY {
        anyhow::bail!("mint would exceed max supply");
    }

    let bal = state.balances.entry(*addr).or_insert(0u128);
    *bal = bal.saturating_add(amount);
    state.total_supply = new_supply;
    Ok(())
}

#[allow(dead_code)]
pub fn transfer_raw(
    state: &mut ChainState,
    from: &Address,
    to: &Address,
    amount: u128,
) -> Result<()> {
    let from_bal = state.balances.entry(*from).or_insert(0u128);
    if *from_bal < amount {
        anyhow::bail!("insufficient funds");
    }

    *from_bal -= amount;
    let to_bal = state.balances.entry(*to).or_insert(0u128);
    *to_bal += amount;
    Ok(())
}