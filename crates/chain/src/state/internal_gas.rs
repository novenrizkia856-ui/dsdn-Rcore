//! # Gas Model Constants & Types (13.9)
//!
//! File ini berisi konstanta dan tipe data untuk gas model DSDN.
//!
//! **CONSENSUS-CRITICAL**: Semua nilai di file ini adalah consensus-critical
//! dan TIDAK BOLEH diubah tanpa hard fork.

// ════════════════════════════════════════════════════════════════════════════
// CONSENSUS-CRITICAL CONSTANTS
// ════════════════════════════════════════════════════════════════════════════
//
// PERINGATAN: Mengubah nilai-nilai ini akan menyebabkan chain split.
// Perubahan HARUS dilakukan melalui hard fork dengan koordinasi network.
//
// ════════════════════════════════════════════════════════════════════════════

/// Base gas cost untuk operasi Transfer (consensus-critical)
pub const BASE_OP_TRANSFER: u64 = 21_000;

/// Base gas cost untuk operasi Storage (consensus-critical)
pub const BASE_OP_STORAGE_OP: u64 = 50_000;

/// Base gas cost untuk operasi Compute (consensus-critical)
pub const BASE_OP_COMPUTE_OP: u64 = 100_000;

/// Cost per byte untuk data payload (consensus-critical)
pub const PER_BYTE_COST: u64 = 16;

/// Cost per compute cycle (consensus-critical)
pub const PER_COMPUTE_CYCLE_COST: u64 = 1;

/// Default node cost index multiplier (consensus-critical)
/// Nilai 100 = 1.0x multiplier (basis 100 untuk fixed-point)
pub const DEFAULT_NODE_COST_INDEX: u128 = 100;

// ════════════════════════════════════════════════════════════════════════════
// GAS BREAKDOWN TYPE
// ════════════════════════════════════════════════════════════════════════════

/// Breakdown detail dari kalkulasi gas untuk satu transaksi.
///
/// Struct ini menyimpan komponen-komponen gas yang digunakan untuk
/// menghitung total fee. Digunakan untuk transparansi dan debugging.
///
/// # Fields
///
/// * `base_op_cost` - Base cost berdasarkan tipe operasi
/// * `data_cost` - Cost dari ukuran data (bytes * PER_BYTE_COST)
/// * `compute_cost` - Cost dari compute cycles (cycles * PER_COMPUTE_CYCLE_COST)
/// * `node_multiplier` - Node cost index multiplier (basis 100)
/// * `total_gas_used` - Total gas sebelum multiplier
/// * `total_fee_cost` - Final fee setelah multiplier (dalam unit terkecil $NUSA)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GasBreakdown {
    /// Base cost berdasarkan tipe operasi (Transfer/Storage/Compute)
    pub base_op_cost: u64,
    
    /// Cost dari ukuran data payload
    pub data_cost: u64,
    
    /// Cost dari compute cycles yang digunakan
    pub compute_cost: u64,
    
    /// Node cost index multiplier (basis 100 = 1.0x)
    pub node_multiplier: u128,
    
    /// Total gas used = base_op_cost + data_cost + compute_cost
    pub total_gas_used: u64,
    
    /// Total fee = total_gas_used * node_multiplier / 100
    pub total_fee_cost: u128,
}

// ════════════════════════════════════════════════════════════════════════════
// GAS CALCULATOR (13.9)
// ════════════════════════════════════════════════════════════════════════════
//
// Fungsi pure untuk menghitung gas berdasarkan payload.
// TIDAK mengubah state, TIDAK menulis log, TIDAK melakukan side-effect.
//
// ════════════════════════════════════════════════════════════════════════════

use crate::types::Address;
use crate::tx::{TxEnvelope, TxPayload};
use super::ChainState;

/// Compute gas for a transaction payload (PURE function)
///
/// # Arguments
/// * `env` - Transaction envelope containing payload
/// * `service_node` - Optional service node address for Storage/Compute operations
/// * `state` - ChainState reference for reading node_cost_index
///
/// # Returns
/// GasBreakdown with all cost components
///
/// # Algorithm
/// 1. Determine base_op_cost based on payload type
/// 2. Calculate data_cost = serialized_size * PER_BYTE_COST
/// 3. Calculate compute_cost = cycles * PER_COMPUTE_CYCLE_COST (if applicable)
/// 4. Get node_multiplier from state (or DEFAULT_NODE_COST_INDEX)
/// 5. Calculate total_gas_used = ceil((base + data + compute) * multiplier / 100)
/// 6. Calculate total_fee_cost = total_gas_used
pub fn compute_gas_for_payload(
    env: &TxEnvelope,
    service_node: Option<Address>,
    state: &ChainState,
) -> GasBreakdown {
    // 1. Determine base_op_cost based on payload type
    let base_op_cost: u64 = match &env.payload {
        TxPayload::Transfer { .. } => BASE_OP_TRANSFER,
        TxPayload::Stake { .. } => BASE_OP_TRANSFER,
        TxPayload::Unstake { .. } => BASE_OP_TRANSFER,
        TxPayload::ClaimReward { .. } => BASE_OP_TRANSFER,
        TxPayload::StorageOperationPayment { .. } => BASE_OP_STORAGE_OP,
        TxPayload::ComputeExecutionPayment { .. } => BASE_OP_COMPUTE_OP,
        TxPayload::ValidatorRegistration { .. } => BASE_OP_TRANSFER,
        TxPayload::GovernanceAction { .. } => BASE_OP_TRANSFER,
        TxPayload::Custom { .. } => BASE_OP_TRANSFER,
    };

    // 2. Calculate data_size using bincode serialization
    let data_size: u64 = bincode::serialized_size(&env.payload).unwrap_or(0);
    let data_cost = data_size * PER_BYTE_COST;

    // 3. Calculate compute_cost
    // ComputeExecutionPayment menggunakan execution_id.len() sebagai proxy
    // untuk compute complexity (field compute_cycles tidak ada di TxPayload)
    let compute_cost: u64 = match &env.payload {
        TxPayload::ComputeExecutionPayment { execution_id, .. } => {
            (execution_id.len() as u64) * PER_COMPUTE_CYCLE_COST
        }
        _ => 0,
    };

    // 4. Get node_multiplier from state
    let node_multiplier: u128 = match service_node {
        Some(addr) => state.get_node_cost_index(&addr),
        None => DEFAULT_NODE_COST_INDEX,
    };

    // 5. Calculate total_gas_used with ceiling division
    // Formula: ceil((base + data + compute) * multiplier / 100)
    let sum = base_op_cost + data_cost + compute_cost;
    let sum_u128 = sum as u128;
    let product = sum_u128 * node_multiplier;
    // Ceiling division: (product + 99) / 100
    let total_gas_used = ((product + 99) / 100) as u64;

    // 6. Calculate total_fee_cost
    let total_fee_cost = total_gas_used as u128;

    // 7. Return GasBreakdown
    GasBreakdown {
        base_op_cost,
        data_cost,
        compute_cost,
        node_multiplier,
        total_gas_used,
        total_fee_cost,
    }
}