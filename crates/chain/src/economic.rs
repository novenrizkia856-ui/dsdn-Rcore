//! # DSDN Economic Controller Constants & Data Structures (13.15)
//!
//! Module ini mendefinisikan FONDASI untuk Adaptive Economic & Deflation Controller.
//!
//! ## Tujuan
//!
//! - Mengontrol burn rate treasury secara dinamis
//! - Menyesuaikan ekonomi berdasarkan RF, usage, treasury, velocity
//! - Target deflasi 3-6% per tahun (adaptif, tidak hard-coded)
//!
//! ## Catatan Penting
//!
//! ```text
//! ⚠️ TAHAP 13.15.1 HANYA DEFINISI:
//! - Tidak ada execution logic
//! - Tidak ada burn logic
//! - Tidak ada state mutation
//! - Ini adalah fondasi untuk controller tahap berikutnya
//!
//! ⚠️ CONSENSUS-CRITICAL:
//! - Semua konstanta memerlukan hard-fork untuk diubah
//! - Urutan enum variant tidak boleh diubah
//! - Urutan struct field tidak boleh diubah
//! ```
//!
//! ## Konstanta Deflasi
//!
//! | Konstanta | Nilai | Keterangan |
//! |-----------|-------|------------|
//! | DEFLATION_TARGET_MIN_PERCENT | 300 | 3% dalam basis points |
//! | DEFLATION_TARGET_MAX_PERCENT | 600 | 6% dalam basis points |
//! | BOOTSTRAP_RF | 3 | Replication Factor fase bootstrap |
//! | BURN_INTERVAL_EPOCHS | 52 | 1x per minggu (epoch = 1 hari) |
//! | MIN_TREASURY_RESERVE | 1_000_000 | Minimum treasury sebelum burn |
//! | VELOCITY_SMOOTHING_FACTOR | 80 | EMA smoothing, 80% weight |
//! | MAX_BURN_PER_EPOCH_PERCENT | 50 | Max 0.5% supply per epoch |

use serde::{Deserialize, Serialize};

// ════════════════════════════════════════════════════════════════════════════
// ECONOMIC CONSTANTS (CONSENSUS-CRITICAL)
// ════════════════════════════════════════════════════════════════════════════
//
// Semua nilai dalam BASIS POINTS (10000 = 100%)
// Perubahan konstanta memerlukan hard-fork.
//
// ════════════════════════════════════════════════════════════════════════════

/// Target deflasi minimum: 3% per tahun (dalam basis points, 10000 = 100%)
pub const DEFLATION_TARGET_MIN_PERCENT: u128 = 300; // 3% (basis points, 10000 = 100%)

/// Target deflasi maksimum: 6% per tahun (dalam basis points, 10000 = 100%)
pub const DEFLATION_TARGET_MAX_PERCENT: u128 = 600; // 6%

/// Replication Factor fase bootstrap (burn minimal/0 saat RF <= ini)
pub const BOOTSTRAP_RF: u8 = 3; // Replication Factor fase bootstrap

/// Interval burn dalam epochs (1x per minggu jika epoch = 1 hari)
pub const BURN_INTERVAL_EPOCHS: u64 = 52; // 1x per minggu (epoch = 1 hari)

/// Minimum treasury balance sebelum burn diizinkan
pub const MIN_TREASURY_RESERVE: u128 = 1_000_000; // minimum treasury sebelum burn

/// EMA smoothing factor untuk token velocity (80% weight ke current)
pub const VELOCITY_SMOOTHING_FACTOR: u128 = 80; // EMA smoothing, 80% weight ke current

/// Maximum burn per epoch: 0.5% dari total supply (dalam basis points)
pub const MAX_BURN_PER_EPOCH_PERCENT: u128 = 50; // max 0.5% supply per epoch

// ════════════════════════════════════════════════════════════════════════════
// ECONOMIC MODE ENUM
// ════════════════════════════════════════════════════════════════════════════
//
// Mode ekonomi menentukan behavior burn:
// - Bootstrap: Fokus akuisisi user, burn minimal/0
// - Active: Burn aktif secara bertahap
// - Governance: Parameter diatur via on-chain governance
//
// ════════════════════════════════════════════════════════════════════════════

/// Mode ekonomi untuk deflation controller
///
/// Mode menentukan bagaimana burn rate dihitung dan dieksekusi.
/// Transisi mode terjadi berdasarkan Replication Factor (RF) atau governance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EconomicMode {
    /// Bootstrap mode: RF <= 3, burn minimal / 0
    /// Fokus pada akuisisi user dan pertumbuhan network
    Bootstrap,
    
    /// Active mode: RF > 3, burn aktif
    /// Deflasi adaptif 3-6% per tahun
    Active,
    
    /// Governance mode: parameter diatur via governance
    /// Diaktifkan setelah network mature
    Governance,
}

impl Default for EconomicMode {
    fn default() -> Self {
        EconomicMode::Bootstrap
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DEFLATION CONFIG STRUCT
// ════════════════════════════════════════════════════════════════════════════
//
// Konfigurasi untuk deflation controller.
// Semua nilai default diambil dari konstanta yang didefinisikan di atas.
//
// ════════════════════════════════════════════════════════════════════════════

/// Konfigurasi deflasi untuk economic controller
///
/// Struct ini menyimpan parameter yang mengontrol burn behavior.
/// Pada Bootstrap mode, burn effectively disabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeflationConfig {
    /// Target deflasi minimum dalam basis points (3% = 300)
    pub target_min_percent: u128,
    
    /// Target deflasi maksimum dalam basis points (6% = 600)
    pub target_max_percent: u128,
    
    /// Interval burn dalam epochs (52 = 1x per minggu)
    pub burn_interval_epochs: u64,
    
    /// Minimum treasury reserve sebelum burn (1_000_000)
    pub min_treasury_reserve: u128,
    
    /// Maximum burn per epoch dalam basis points (50 = 0.5%)
    pub max_burn_per_epoch_percent: u128,
    
    /// Mode ekonomi saat ini
    pub mode: EconomicMode,
    
    /// Apakah deflasi diaktifkan
    pub enabled: bool,
    pub replication_factor: u8,
}

impl Default for DeflationConfig {
    fn default() -> Self {
        Self {
            target_min_percent: DEFLATION_TARGET_MIN_PERCENT,
            target_max_percent: DEFLATION_TARGET_MAX_PERCENT,
            burn_interval_epochs: BURN_INTERVAL_EPOCHS,
            min_treasury_reserve: MIN_TREASURY_RESERVE,
            max_burn_per_epoch_percent: MAX_BURN_PER_EPOCH_PERCENT,
            mode: EconomicMode::Bootstrap,
            enabled: true,
            replication_factor: 1,
        }
    }
}

impl DeflationConfig {
    /// Membuat DeflationConfig untuk fase bootstrap
    ///
    /// Mode = Bootstrap, burn effectively minimal/disabled.
    /// Konsisten dengan Default secara semantik.
    pub fn new_bootstrap() -> Self {
        Self {
            target_min_percent: DEFLATION_TARGET_MIN_PERCENT,
            target_max_percent: DEFLATION_TARGET_MAX_PERCENT,
            burn_interval_epochs: BURN_INTERVAL_EPOCHS,
            min_treasury_reserve: MIN_TREASURY_RESERVE,
            max_burn_per_epoch_percent: MAX_BURN_PER_EPOCH_PERCENT,
            mode: EconomicMode::Bootstrap,
            enabled: true,
            replication_factor: 1,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// ECONOMIC METRICS STRUCT
// ════════════════════════════════════════════════════════════════════════════
//
// Metrics ekonomi yang digunakan untuk menghitung burn rate adaptif.
// Di-update setiap epoch atau block.
//
// ════════════════════════════════════════════════════════════════════════════

/// Metrics ekonomi untuk adaptive burn rate calculation
///
/// Struct ini menyimpan data ekonomi yang mempengaruhi burn rate:
/// - Replication Factor (RF) - higher = higher burn
/// - Network usage - higher = stable burn
/// - Token velocity - higher velocity = lower burn
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicMetrics {
    /// Replication Factor saat ini
    pub replication_factor: u8,
    
    /// Total storage usage dalam bytes
    pub storage_usage_bytes: u128,
    
    /// Total compute cycles yang digunakan
    pub compute_cycles_used: u128,
    
    /// Jumlah node aktif
    pub active_nodes: u64,
    
    /// Jumlah validator aktif
    pub active_validators: u64,
    
    /// Token velocity (transfer volume / time)
    pub token_velocity: u128,
    
    /// Treasury inflow untuk epoch saat ini (dari fees)
    pub treasury_inflow_epoch: u128,
    
    /// Slashing inflow untuk epoch saat ini
    pub slashing_inflow_epoch: u128,
    
    /// Epoch terakhir metrics di-update
    pub last_updated_epoch: u64,
}

impl Default for EconomicMetrics {
    fn default() -> Self {
        Self {
            replication_factor: BOOTSTRAP_RF,
            storage_usage_bytes: 0,
            compute_cycles_used: 0,
            active_nodes: 0,
            active_validators: 0,
            token_velocity: 0,
            treasury_inflow_epoch: 0,
            slashing_inflow_epoch: 0,
            last_updated_epoch: 0,
        }
    }
}

impl EconomicMetrics {
    /// Membuat EconomicMetrics baru dengan state kosong & deterministik
    ///
    /// Sama dengan Default secara semantik.
    pub fn new() -> Self {
        Self {
            replication_factor: BOOTSTRAP_RF,
            storage_usage_bytes: 0,
            compute_cycles_used: 0,
            active_nodes: 0,
            active_validators: 0,
            token_velocity: 0,
            treasury_inflow_epoch: 0,
            slashing_inflow_epoch: 0,
            last_updated_epoch: 0,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// BURN EVENT STRUCT
// ════════════════════════════════════════════════════════════════════════════
//
// Record dari setiap burn event untuk audit trail.
// Tidak dipersist ke LMDB (runtime-only).
//
// ════════════════════════════════════════════════════════════════════════════

/// Event record untuk setiap treasury burn
///
/// Digunakan untuk audit trail dan observability.
/// Runtime-only, tidak dipersist ke LMDB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnEvent {
    /// Epoch saat burn terjadi
    pub epoch: u64,
    
    /// Jumlah token yang di-burn
    pub amount_burned: u128,
    
    /// Treasury balance sebelum burn
    pub treasury_before: u128,
    
    /// Treasury balance setelah burn
    pub treasury_after: u128,
    
    /// Total supply sebelum burn
    pub total_supply_before: u128,
    
    /// Total supply setelah burn
    pub total_supply_after: u128,
    
    /// Burn rate yang diterapkan (basis points)
    pub burn_rate_applied: u128,
    
    /// Unix timestamp saat burn
    pub timestamp: u64,
}

// ════════════════════════════════════════════════════════════════════════════
// ECONOMIC SNAPSHOT STRUCT
// ════════════════════════════════════════════════════════════════════════════
//
// Snapshot lengkap state ekonomi untuk audit dan observability.
//
// ════════════════════════════════════════════════════════════════════════════

/// Snapshot lengkap state ekonomi
///
/// Digunakan untuk audit, RPC query, dan economic analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicSnapshot {
    /// Epoch saat snapshot diambil
    pub epoch: u64,
    
    /// Metrics ekonomi saat ini
    pub metrics: EconomicMetrics,
    
    /// Konfigurasi deflasi saat ini
    pub config: DeflationConfig,
    
    /// Treasury balance saat ini
    pub treasury_balance: u128,
    
    /// Total supply saat ini
    pub total_supply: u128,
    
    /// Annual burn rate aktual (basis points)
    pub annual_burn_rate: u128,
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_economic_constants() {
        // Verify all constants match specification exactly
        assert_eq!(DEFLATION_TARGET_MIN_PERCENT, 300, "Min deflation should be 3% (300 bp)");
        assert_eq!(DEFLATION_TARGET_MAX_PERCENT, 600, "Max deflation should be 6% (600 bp)");
        assert_eq!(BOOTSTRAP_RF, 3, "Bootstrap RF should be 3");
        assert_eq!(BURN_INTERVAL_EPOCHS, 52, "Burn interval should be 52 epochs");
        assert_eq!(MIN_TREASURY_RESERVE, 1_000_000, "Min treasury reserve should be 1M");
        assert_eq!(VELOCITY_SMOOTHING_FACTOR, 80, "Velocity smoothing should be 80");
        assert_eq!(MAX_BURN_PER_EPOCH_PERCENT, 50, "Max burn per epoch should be 0.5% (50 bp)");
    }

    #[test]
    fn test_economic_mode_variants() {
        // Verify all enum variants are instantiable
        let bootstrap = EconomicMode::Bootstrap;
        let active = EconomicMode::Active;
        let governance = EconomicMode::Governance;
        
        assert_eq!(bootstrap, EconomicMode::Bootstrap);
        assert_eq!(active, EconomicMode::Active);
        assert_eq!(governance, EconomicMode::Governance);
        
        // Verify they are distinct
        assert_ne!(bootstrap, active);
        assert_ne!(active, governance);
        assert_ne!(bootstrap, governance);
    }

    #[test]
    fn test_economic_mode_default() {
        let mode = EconomicMode::default();
        assert_eq!(mode, EconomicMode::Bootstrap, "Default mode should be Bootstrap");
    }

    #[test]
    fn test_deflation_config_default() {
        let config = DeflationConfig::default();
        
        assert_eq!(config.target_min_percent, DEFLATION_TARGET_MIN_PERCENT);
        assert_eq!(config.target_max_percent, DEFLATION_TARGET_MAX_PERCENT);
        assert_eq!(config.burn_interval_epochs, BURN_INTERVAL_EPOCHS);
        assert_eq!(config.min_treasury_reserve, MIN_TREASURY_RESERVE);
        assert_eq!(config.max_burn_per_epoch_percent, MAX_BURN_PER_EPOCH_PERCENT);
        assert_eq!(config.mode, EconomicMode::Bootstrap);
        assert!(config.enabled, "Deflation should be enabled by default");
    }

    #[test]
    fn test_deflation_config_new_bootstrap() {
        let config = DeflationConfig::new_bootstrap();
        let default_config = DeflationConfig::default();
        
        // new_bootstrap should be semantically identical to default
        assert_eq!(config.target_min_percent, default_config.target_min_percent);
        assert_eq!(config.target_max_percent, default_config.target_max_percent);
        assert_eq!(config.burn_interval_epochs, default_config.burn_interval_epochs);
        assert_eq!(config.min_treasury_reserve, default_config.min_treasury_reserve);
        assert_eq!(config.max_burn_per_epoch_percent, default_config.max_burn_per_epoch_percent);
        assert_eq!(config.mode, EconomicMode::Bootstrap);
        assert!(config.enabled);
    }

    #[test]
    fn test_economic_metrics_default() {
        let metrics = EconomicMetrics::default();
        
        assert_eq!(metrics.replication_factor, BOOTSTRAP_RF);
        assert_eq!(metrics.storage_usage_bytes, 0);
        assert_eq!(metrics.compute_cycles_used, 0);
        assert_eq!(metrics.active_nodes, 0);
        assert_eq!(metrics.active_validators, 0);
        assert_eq!(metrics.token_velocity, 0);
        assert_eq!(metrics.treasury_inflow_epoch, 0);
        assert_eq!(metrics.slashing_inflow_epoch, 0);
        assert_eq!(metrics.last_updated_epoch, 0);
    }

    #[test]
    fn test_economic_metrics_new() {
        let metrics = EconomicMetrics::new();
        let default_metrics = EconomicMetrics::default();
        
        // new() should be semantically identical to default
        assert_eq!(metrics.replication_factor, default_metrics.replication_factor);
        assert_eq!(metrics.storage_usage_bytes, default_metrics.storage_usage_bytes);
        assert_eq!(metrics.compute_cycles_used, default_metrics.compute_cycles_used);
        assert_eq!(metrics.active_nodes, default_metrics.active_nodes);
        assert_eq!(metrics.active_validators, default_metrics.active_validators);
        assert_eq!(metrics.token_velocity, default_metrics.token_velocity);
        assert_eq!(metrics.treasury_inflow_epoch, default_metrics.treasury_inflow_epoch);
        assert_eq!(metrics.slashing_inflow_epoch, default_metrics.slashing_inflow_epoch);
        assert_eq!(metrics.last_updated_epoch, default_metrics.last_updated_epoch);
    }

    #[test]
    fn test_burn_event_creation() {
        let event = BurnEvent {
            epoch: 100,
            amount_burned: 50_000,
            treasury_before: 10_000_000,
            treasury_after: 9_950_000,
            total_supply_before: 1_000_000_000,
            total_supply_after: 999_950_000,
            burn_rate_applied: 450, // 4.5%
            timestamp: 1700000000,
        };
        
        assert_eq!(event.epoch, 100);
        assert_eq!(event.amount_burned, 50_000);
        assert_eq!(event.treasury_before, 10_000_000);
        assert_eq!(event.treasury_after, 9_950_000);
        assert_eq!(event.total_supply_before, 1_000_000_000);
        assert_eq!(event.total_supply_after, 999_950_000);
        assert_eq!(event.burn_rate_applied, 450);
        assert_eq!(event.timestamp, 1700000000);
        
        // Verify arithmetic consistency
        assert_eq!(event.treasury_before - event.treasury_after, event.amount_burned);
        assert_eq!(event.total_supply_before - event.total_supply_after, event.amount_burned);
    }

    #[test]
    fn test_economic_snapshot_creation() {
        let snapshot = EconomicSnapshot {
            epoch: 200,
            metrics: EconomicMetrics::new(),
            config: DeflationConfig::new_bootstrap(),
            treasury_balance: 5_000_000,
            total_supply: 500_000_000,
            annual_burn_rate: 400, // 4%
        };
        
        assert_eq!(snapshot.epoch, 200);
        assert_eq!(snapshot.metrics.replication_factor, BOOTSTRAP_RF);
        assert_eq!(snapshot.config.mode, EconomicMode::Bootstrap);
        assert_eq!(snapshot.treasury_balance, 5_000_000);
        assert_eq!(snapshot.total_supply, 500_000_000);
        assert_eq!(snapshot.annual_burn_rate, 400);
    }

    #[test]
    fn test_basis_points_consistency() {
        // Verify basis points interpretation is correct
        // 10000 bp = 100%, so:
        // 300 bp = 3%
        // 600 bp = 6%
        // 50 bp = 0.5%
        
        let total = 1_000_000u128;
        
        let min_deflation = (total * DEFLATION_TARGET_MIN_PERCENT) / 10_000;
        assert_eq!(min_deflation, 30_000, "3% of 1M should be 30K");
        
        let max_deflation = (total * DEFLATION_TARGET_MAX_PERCENT) / 10_000;
        assert_eq!(max_deflation, 60_000, "6% of 1M should be 60K");
        
        let max_burn_epoch = (total * MAX_BURN_PER_EPOCH_PERCENT) / 10_000;
        assert_eq!(max_burn_epoch, 5_000, "0.5% of 1M should be 5K");
    }
}