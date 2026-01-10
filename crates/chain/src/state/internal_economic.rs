//! # Economic Metrics Tracking & Burn Rate Calculation (13.15.3 + 13.15.4 + 13.15.5)
//!
//! Module ini menyediakan TRACKING & UPDATE ECONOMIC METRICS untuk ChainState,
//! ALGORITMA PERHITUNGAN BURN RATE ADAPTIF, dan EKSEKUSI TREASURY BURN.
//!
//! ## Karakteristik
//!
//! ```text
//! ⚠️ CONSENSUS-CRITICAL:
//! - Semua update deterministik
//! - Tidak menggunakan float
//! - Tidak menggunakan random
//! - Hasil identik di semua node
//!
//! ⚠️ DIGUNAKAN OLEH:
//! - Burn rate calculator (13.15.4)
//! - Treasury burn executor (13.15.5)
//! - Economic RPC/CLI (13.15.8)
//! ```
//!
//! ## Methods Overview (13.15.3)
//!
//! | Method | Fungsi |
//! |--------|--------|
//! | `update_replication_factor` | Update RF, mode change ke Active |
//! | `record_storage_usage` | Akumulasi storage bytes |
//! | `record_compute_usage` | Akumulasi compute cycles |
//! | `update_token_velocity` | EMA velocity calculation |
//! | `record_treasury_inflow` | Track fee/slashing inflow |
//! | `reset_epoch_metrics` | Reset per-epoch counters |
//! | `get_economic_mode` | Get current economic mode |
//! | `update_active_counts` | Count active nodes/validators |
//! | `get_economic_snapshot` | Full economic snapshot |
//!
//! ## Burn Rate Calculation (13.15.4)
//!
//! | Method | Fungsi |
//! |--------|--------|
//! | `calculate_target_burn_rate` | Hitung adaptive burn rate (basis points) |
//! | `calculate_burn_amount` | Hitung jumlah burn untuk epoch |
//! | `should_burn` | Check apakah burn harus dilakukan |
//! | `get_rf_multiplier` | RF-based multiplier (basis 100) |
//! | `get_velocity_factor` | Velocity-based factor (basis 100) |
//!
//! ## Treasury Burn Execution (13.15.5)
//!
//! | Method | Fungsi |
//! |--------|--------|
//! | `execute_treasury_burn` | Eksekusi burn dari treasury dengan validasi lengkap |
//! | `burn_from_treasury` | Low-level burn untuk testing/manual (tanpa event) |
//! | `get_annual_burn_rate` | Hitung annual burn rate dalam basis points |
//! | `get_burn_history` | Akses read-only ke semua BurnEvent |
//!
//! ## Error Types (13.15.5)
//!
//! | Error | Deskripsi |
//! |-------|-----------|
//! | `EconomicError::InsufficientTreasury` | Treasury tidak cukup |
//! | `EconomicError::BurnDisabled` | Burn tidak diizinkan |
//! | `EconomicError::InvalidAmount` | Amount tidak valid (0) |
//! | `EconomicError::NotYetDue` | Burn interval belum tercapai |

use super::ChainState;
use crate::economic::{
    BurnEvent,
    EconomicMode,
    EconomicSnapshot,
    BOOTSTRAP_RF,
    VELOCITY_SMOOTHING_FACTOR,
    DEFLATION_TARGET_MIN_PERCENT,
    DEFLATION_TARGET_MAX_PERCENT,
    MIN_TREASURY_RESERVE,
    MAX_BURN_PER_EPOCH_PERCENT,
};

// ════════════════════════════════════════════════════════════════════════════
// ECONOMIC ERROR (13.15.5)
// ════════════════════════════════════════════════════════════════════════════
//
// Error types untuk treasury burn operations.
// CONSENSUS-CRITICAL: Tidak boleh menambah variant lain.
//
// ════════════════════════════════════════════════════════════════════════════

/// Error type untuk treasury burn operations
///
/// # Variants (TIDAK BOLEH DITAMBAH)
/// - `InsufficientTreasury`: Treasury balance tidak cukup untuk burn
/// - `BurnDisabled`: Burn tidak diizinkan (disabled atau Bootstrap mode)
/// - `InvalidAmount`: Amount tidak valid (e.g., 0)
/// - `NotYetDue`: Burn interval belum tercapai
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EconomicError {
    /// Treasury balance tidak cukup untuk burn yang diminta
    InsufficientTreasury,
    /// Burn tidak diizinkan saat ini (disabled atau Bootstrap mode)
    BurnDisabled,
    /// Amount yang diberikan tidak valid (e.g., 0)
    InvalidAmount,
    /// Burn interval belum tercapai, burn belum waktunya
    NotYetDue,
}

// ════════════════════════════════════════════════════════════════════════════
// VELOCITY THRESHOLDS (CONSENSUS-CRITICAL)
// ════════════════════════════════════════════════════════════════════════════
//
// Threshold untuk menentukan kategori velocity.
// Nilai dalam unit token velocity (transfer volume per epoch).
//
// Low velocity: < VELOCITY_THRESHOLD_LOW → 100 (no adjustment)
// Medium velocity: VELOCITY_THRESHOLD_LOW..VELOCITY_THRESHOLD_HIGH → 90
// High velocity: >= VELOCITY_THRESHOLD_HIGH → 80 (reduce burn)
//
// ════════════════════════════════════════════════════════════════════════════

/// Threshold velocity rendah: di bawah ini = low velocity
const VELOCITY_THRESHOLD_LOW: u128 = 1_000_000;

/// Threshold velocity tinggi: di atas ini = high velocity
const VELOCITY_THRESHOLD_HIGH: u128 = 10_000_000;

/// Epochs per year (1 epoch = 1 day)
const EPOCHS_PER_YEAR: u128 = 365;

impl ChainState {
    // ════════════════════════════════════════════════════════════════════════════
    // REPLICATION FACTOR UPDATE
    // ════════════════════════════════════════════════════════════════════════════

    /// Update replication factor dan potentially switch mode ke Active
    ///
    /// # Arguments
    /// * `rf` - Replication factor baru
    ///
    /// # Behavior
    /// - Update `economic_metrics.replication_factor`
    /// - Jika `rf > BOOTSTRAP_RF` dan deflation enabled: mode → Active
    /// - Jika deflation disabled: mode tetap Bootstrap
    ///
    /// # Consensus-Critical
    /// Deterministik, tidak ada side effect selain state update.
    pub fn update_replication_factor(&mut self, rf: u8) {
        self.economic_metrics.replication_factor = rf;
        
        // Mode transition: Bootstrap → Active
        // Hanya jika deflation enabled dan RF > bootstrap threshold
        if self.deflation_config.enabled 
            && rf > BOOTSTRAP_RF 
            && self.deflation_config.mode == EconomicMode::Bootstrap 
        {
            self.deflation_config.mode = EconomicMode::Active;
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // USAGE TRACKING
    // ════════════════════════════════════════════════════════════════════════════

    /// Record storage usage (bytes)
    ///
    /// # Arguments
    /// * `bytes` - Jumlah bytes yang digunakan
    ///
    /// # Behavior
    /// Akumulasi ke `storage_usage_bytes` dengan saturating add (overflow-safe).
    pub fn record_storage_usage(&mut self, bytes: u128) {
        self.economic_metrics.storage_usage_bytes = 
            self.economic_metrics.storage_usage_bytes.saturating_add(bytes);
    }

    /// Record compute usage (cycles)
    ///
    /// # Arguments
    /// * `cycles` - Jumlah compute cycles yang digunakan
    ///
    /// # Behavior
    /// Akumulasi ke `compute_cycles_used` dengan saturating add (overflow-safe).
    pub fn record_compute_usage(&mut self, cycles: u128) {
        self.economic_metrics.compute_cycles_used = 
            self.economic_metrics.compute_cycles_used.saturating_add(cycles);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // TOKEN VELOCITY
    // ════════════════════════════════════════════════════════════════════════════

    /// Update token velocity using Exponential Moving Average (EMA)
    ///
    /// # Arguments
    /// * `transfer_volume` - Total transfer volume untuk epoch ini
    /// * `current_epoch` - Epoch saat ini
    ///
    /// # Formula
    /// ```text
    /// velocity = transfer_volume / 1 (epoch duration dianggap konstan)
    /// new_velocity = (VELOCITY_SMOOTHING_FACTOR * velocity 
    ///                + (100 - VELOCITY_SMOOTHING_FACTOR) * old_velocity) / 100
    /// ```
    ///
    /// # Behavior
    /// - Hitung velocity baru dengan EMA smoothing
    /// - Update `token_velocity` dan `last_updated_epoch`
    /// - Tidak panic jika old_velocity = 0
    ///
    /// # Consensus-Critical
    /// - Tidak menggunakan float
    /// - Deterministik (integer arithmetic only)
    pub fn update_token_velocity(&mut self, transfer_volume: u128, current_epoch: u64) {
        // Epoch duration dianggap konstan = 1 untuk simplicity
        // velocity = transfer_volume / epoch_duration = transfer_volume
        let velocity = transfer_volume;
        
        let old_velocity = self.economic_metrics.token_velocity;
        
        // EMA calculation (integer arithmetic)
        // new_velocity = (SMOOTHING * velocity + (100 - SMOOTHING) * old_velocity) / 100
        let smoothing = VELOCITY_SMOOTHING_FACTOR;
        let complement = 100u128.saturating_sub(smoothing);
        
        let weighted_new = smoothing.saturating_mul(velocity);
        let weighted_old = complement.saturating_mul(old_velocity);
        
        let new_velocity = weighted_new.saturating_add(weighted_old) / 100;
        
        self.economic_metrics.token_velocity = new_velocity;
        self.economic_metrics.last_updated_epoch = current_epoch;
    }

    // ════════════════════════════════════════════════════════════════════════════
    // TREASURY INFLOW TRACKING
    // ════════════════════════════════════════════════════════════════════════════

    /// Record treasury inflow dari fee atau slashing
    ///
    /// # Arguments
    /// * `amount` - Jumlah inflow
    /// * `source` - Sumber inflow: "fee" atau "slashing"
    ///
    /// # Behavior
    /// - "fee" → treasury_inflow_epoch += amount
    /// - "slashing" → slashing_inflow_epoch += amount
    /// - Sumber lain → IGNORE (tidak panic, tidak error)
    ///
    /// # Consensus-Critical
    /// Overflow-safe dengan saturating add.
    pub fn record_treasury_inflow(&mut self, amount: u128, source: &str) {
        match source {
            "fee" => {
                self.economic_metrics.treasury_inflow_epoch = 
                    self.economic_metrics.treasury_inflow_epoch.saturating_add(amount);
            }
            "slashing" => {
                self.economic_metrics.slashing_inflow_epoch = 
                    self.economic_metrics.slashing_inflow_epoch.saturating_add(amount);
            }
            _ => {
                // IGNORE unknown source - tidak panic, tidak error
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // EPOCH RESET
    // ════════════════════════════════════════════════════════════════════════════

    /// Reset per-epoch metrics counters
    ///
    /// # Arguments
    /// * `new_epoch` - Epoch baru
    ///
    /// # Behavior
    /// - treasury_inflow_epoch = 0
    /// - slashing_inflow_epoch = 0
    /// - last_updated_epoch = new_epoch
    ///
    /// # When to Call
    /// Dipanggil pada epoch transition.
    pub fn reset_epoch_metrics(&mut self, new_epoch: u64) {
        self.economic_metrics.treasury_inflow_epoch = 0;
        self.economic_metrics.slashing_inflow_epoch = 0;
        self.economic_metrics.last_updated_epoch = new_epoch;
    }

    // ════════════════════════════════════════════════════════════════════════════
    // MODE DETECTION
    // ════════════════════════════════════════════════════════════════════════════

    /// Get current economic mode
    ///
    /// # Returns
    /// `EconomicMode` berdasarkan state saat ini.
    ///
    /// # Logic
    /// ```text
    /// 1. Jika deflation disabled → Bootstrap
    /// 2. Jika mode == Governance → Governance
    /// 3. Jika RF > BOOTSTRAP_RF → Active
    /// 4. Else → Bootstrap
    /// ```
    ///
    /// # Note
    /// Tidak mengubah state, hanya membaca.
    pub fn get_economic_mode(&self) -> EconomicMode {
        // Jika deflation disabled, selalu Bootstrap
        if !self.deflation_config.enabled {
            return EconomicMode::Bootstrap;
        }
        
        // Jika mode sudah Governance, return Governance
        if self.deflation_config.mode == EconomicMode::Governance {
            return EconomicMode::Governance;
        }
        
        // Jika RF > bootstrap threshold, return Active
        if self.economic_metrics.replication_factor > BOOTSTRAP_RF {
            return EconomicMode::Active;
        }
        
        // Default: Bootstrap
        EconomicMode::Bootstrap
    }

    // ════════════════════════════════════════════════════════════════════════════
    // ACTIVE COUNTS UPDATE
    // ════════════════════════════════════════════════════════════════════════════

    /// Update active nodes dan validators count
    ///
    /// # Behavior
    /// - `active_nodes`: Count nodes yang TIDAK force-unbonded
    /// - `active_validators`: Count validators yang active
    ///
    /// # Implementation Details
    /// - Node dianggap aktif jika `force_unbond_until` is None
    /// - Validator dianggap aktif jika `validator_set.is_active(addr)` or active flag
    ///
    /// # Consensus-Critical
    /// Tidak panic jika maps kosong.
    pub fn update_active_counts(&mut self) {
        // Count active nodes
        // Node dianggap aktif jika TIDAK force-unbonded
        let active_nodes_count = self.node_liveness_records.values()
            .filter(|record| record.force_unbond_until.is_none())
            .count() as u64;
        
        self.economic_metrics.active_nodes = active_nodes_count;
        
        // Count active validators
        // Gunakan validator_set untuk mendapatkan count validator aktif
        let active_validators_count = self.validator_set.active_count() as u64;
        
        self.economic_metrics.active_validators = active_validators_count;
    }

    // ════════════════════════════════════════════════════════════════════════════
    // SNAPSHOT
    // ════════════════════════════════════════════════════════════════════════════

    /// Get complete economic snapshot
    ///
    /// # Returns
    /// `EconomicSnapshot` dengan semua data ekonomi saat ini.
    ///
    /// # Behavior
    /// - Clone metrics dan config
    /// - Include treasury_balance dan total_supply
    /// - Calculate annual_burn_rate dari cumulative data
    ///
    /// # Note
    /// - Tidak ada mutable reference
    /// - Tidak ada side effect
    /// - Safe untuk concurrent read
    pub fn get_economic_snapshot(&self) -> EconomicSnapshot {
        // Calculate annual burn rate (basis points)
        // Simplified: ratio of cumulative_burned to initial supply estimate
        // In production, this would use more sophisticated calculation
        let annual_burn_rate = if self.total_supply > 0 {
            // Estimate: (cumulative_burned / total_supply) * 10000 as basis points
            // Simplified approximation
            (self.cumulative_burned.saturating_mul(10_000)) / self.total_supply.max(1)
        } else {
            0
        };
        
        EconomicSnapshot {
            epoch: self.epoch_info.epoch_number,
            metrics: self.economic_metrics.clone(),
            config: self.deflation_config.clone(),
            treasury_balance: self.treasury_balance,
            total_supply: self.total_supply,
            annual_burn_rate,
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // BURN RATE CALCULATION (13.15.4)
    // ════════════════════════════════════════════════════════════════════════════
    //
    // Algoritma perhitungan burn rate adaptif.
    // Target deflasi 3-6% per tahun, disesuaikan berdasarkan:
    // - Replication Factor (RF)
    // - Token velocity
    // - Treasury health
    //
    // CONSENSUS-CRITICAL: Semua perhitungan integer-only, deterministik.
    //
    // ════════════════════════════════════════════════════════════════════════════

    /// Calculate target burn rate (basis points)
    ///
    /// # Returns
    /// Burn rate dalam basis points (10000 = 100%)
    /// Range: 0 atau [DEFLATION_TARGET_MIN_PERCENT, DEFLATION_TARGET_MAX_PERCENT]
    ///
    /// # Algorithm (URUTAN TIDAK BOLEH DIUBAH)
    /// ```text
    /// 1. Bootstrap mode → return 0
    /// 2. Treasury < MIN_RESERVE → return 0
    /// 3. base = (TARGET_MIN + TARGET_MAX) / 2
    /// 4. adjusted = base * rf_multiplier / 100
    /// 5. adjusted = adjusted * velocity_factor / 100
    /// 6. Treasury adjustment (≤ +5%)
    /// 7. Clamp to [TARGET_MIN, TARGET_MAX]
    /// ```
    ///
    /// # Consensus-Critical
    /// - Integer-only arithmetic
    /// - No overflow (saturating ops)
    /// - No side effects
    /// - Deterministik di semua node
    pub fn calculate_target_burn_rate(&self) -> u128 {
        // Step 1: Bootstrap mode → return 0
        if self.get_economic_mode() == EconomicMode::Bootstrap {
            return 0;
        }
        
        // Step 2: Treasury < MIN_RESERVE → return 0
        if self.treasury_balance < MIN_TREASURY_RESERVE {
            return 0;
        }
        
        // Step 3: Calculate base rate (average of min and max)
        // base = (300 + 600) / 2 = 450 basis points (4.5%)
        let base_rate = (DEFLATION_TARGET_MIN_PERCENT + DEFLATION_TARGET_MAX_PERCENT) / 2;
        
        // Step 4: Apply RF multiplier (basis 100)
        let rf_multiplier = self.get_rf_multiplier();
        let adjusted = base_rate.saturating_mul(rf_multiplier) / 100;
        
        // Step 5: Apply velocity factor (basis 100)
        let velocity_factor = self.get_velocity_factor();
        let adjusted = adjusted.saturating_mul(velocity_factor) / 100;
        
        // Step 6: Treasury adjustment
        // Jika treasury jauh di atas minimum, naikkan burn sedikit (max +5%)
        // treasury_ratio = treasury_balance / MIN_TREASURY_RESERVE
        // Jika ratio >= 10x → add 5% (50 basis points)
        // Jika ratio >= 5x → add 3% (30 basis points)
        // Else → no adjustment
        let treasury_ratio = self.treasury_balance / MIN_TREASURY_RESERVE.max(1);
        let treasury_adjustment = if treasury_ratio >= 10 {
            50 // +0.5% (50 basis points)
        } else if treasury_ratio >= 5 {
            30 // +0.3% (30 basis points)
        } else {
            0 // no adjustment
        };
        let adjusted = adjusted.saturating_add(treasury_adjustment);
        
        // Step 7: Clamp to valid range [TARGET_MIN, TARGET_MAX]
        let final_rate = if adjusted < DEFLATION_TARGET_MIN_PERCENT {
            DEFLATION_TARGET_MIN_PERCENT
        } else if adjusted > DEFLATION_TARGET_MAX_PERCENT {
            DEFLATION_TARGET_MAX_PERCENT
        } else {
            adjusted
        };
        
        final_rate
    }

    /// Calculate burn amount for current epoch
    ///
    /// # Arguments
    /// * `rate` - Burn rate dalam basis points (dari calculate_target_burn_rate)
    ///
    /// # Returns
    /// Jumlah token yang akan di-burn untuk epoch ini
    ///
    /// # Algorithm
    /// ```text
    /// 1. annual_burn = total_supply * rate / 10000
    /// 2. epoch_burn = annual_burn / EPOCHS_PER_YEAR
    /// 3. Clamp to max_burn_per_epoch
    /// 4. Clamp to treasury_balance - MIN_RESERVE
    /// 5. Return 0 jika hasil negatif/nol
    /// ```
    ///
    /// # Consensus-Critical
    /// - Integer-only arithmetic
    /// - Overflow-safe (saturating ops)
    /// - Treasury protection (never burn below reserve)
    pub fn calculate_burn_amount(&self, rate: u128) -> u128 {
        // Early return jika rate = 0
        if rate == 0 {
            return 0;
        }
        
        // Early return jika total_supply = 0
        if self.total_supply == 0 {
            return 0;
        }
        
        // Step 1-2: Calculate epoch burn amount
        // epoch_burn = (total_supply * rate) / (10000 * epochs_per_year)
        // Split calculation to avoid overflow
        let annual_burn = self.total_supply.saturating_mul(rate) / 10_000;
        let epoch_burn = annual_burn / EPOCHS_PER_YEAR;
        
        // Step 3: Clamp to max_burn_per_epoch
        // max_burn = total_supply * MAX_BURN_PER_EPOCH_PERCENT / 10000
        let max_burn_per_epoch = self.total_supply
            .saturating_mul(MAX_BURN_PER_EPOCH_PERCENT) / 10_000;
        let amount = epoch_burn.min(max_burn_per_epoch);
        
        // Step 4: Clamp to treasury_balance - MIN_RESERVE
        // Ensure we never burn below reserve
        let available_for_burn = if self.treasury_balance > MIN_TREASURY_RESERVE {
            self.treasury_balance - MIN_TREASURY_RESERVE
        } else {
            0
        };
        let amount = amount.min(available_for_burn);
        
        // Step 5: Return final amount (0 if none available)
        amount
    }

    /// Check if burn should be executed this epoch
    ///
    /// # Arguments
    /// * `current_epoch` - Epoch saat ini
    ///
    /// # Returns
    /// `true` jika SEMUA kondisi burn terpenuhi
    ///
    /// # Conditions (ALL must be true)
    /// ```text
    /// 1. deflation_config.enabled == true
    /// 2. get_economic_mode() != Bootstrap
    /// 3. current_epoch - last_burn_epoch >= burn_interval_epochs
    /// 4. treasury_balance > MIN_TREASURY_RESERVE
    /// ```
    ///
    /// # Consensus-Critical
    /// Deterministik, no side effects.
    pub fn should_burn(&self, current_epoch: u64) -> bool {
        // Condition 1: Deflation must be enabled
        if !self.deflation_config.enabled {
            return false;
        }
        
        // Condition 2: Must not be in Bootstrap mode
        if self.get_economic_mode() == EconomicMode::Bootstrap {
            return false;
        }
        
        // Condition 3: Must have passed burn interval
        // current_epoch - last_burn_epoch >= burn_interval_epochs
        let epochs_since_last_burn = current_epoch.saturating_sub(self.last_burn_epoch);
        if epochs_since_last_burn < self.deflation_config.burn_interval_epochs {
            return false;
        }
        
        // Condition 4: Treasury must be above minimum reserve
        if self.treasury_balance <= MIN_TREASURY_RESERVE {
            return false;
        }
        
        // All conditions met
        true
    }

    /// Get RF-based multiplier for burn rate
    ///
    /// # Returns
    /// Multiplier dalam basis 100:
    /// - RF = 3 → 100 (1.0x, no change)
    /// - RF = 4 → 120 (1.2x)
    /// - RF = 5 → 140 (1.4x)
    /// - RF >= 6 → 160 (1.6x)
    ///
    /// # Rationale
    /// Higher RF = more decentralized = higher confidence = more burn
    ///
    /// # Consensus-Critical
    /// Fixed mapping, no interpolation, no float.
    pub fn get_rf_multiplier(&self) -> u128 {
        let rf = self.economic_metrics.replication_factor;
        
        match rf {
            0..=3 => 100,  // RF <= 3: 1.0x (baseline, but should be Bootstrap)
            4 => 120,      // RF = 4: 1.2x
            5 => 140,      // RF = 5: 1.4x
            _ => 160,      // RF >= 6: 1.6x (max multiplier)
        }
    }

    /// Get velocity-based factor for burn rate
    ///
    /// # Returns
    /// Factor dalam basis 100:
    /// - Low velocity (< THRESHOLD_LOW) → 100 (no reduction)
    /// - Medium velocity (THRESHOLD_LOW..THRESHOLD_HIGH) → 90
    /// - High velocity (>= THRESHOLD_HIGH) → 80
    ///
    /// # Rationale
    /// Higher velocity = more economic activity = reduce burn to maintain liquidity
    ///
    /// # Thresholds
    /// - VELOCITY_THRESHOLD_LOW: 1_000_000
    /// - VELOCITY_THRESHOLD_HIGH: 10_000_000
    ///
    /// # Consensus-Critical
    /// Fixed thresholds, no interpolation, no float.
    pub fn get_velocity_factor(&self) -> u128 {
        let velocity = self.economic_metrics.token_velocity;
        
        if velocity < VELOCITY_THRESHOLD_LOW {
            100  // Low velocity: no reduction
        } else if velocity < VELOCITY_THRESHOLD_HIGH {
            90   // Medium velocity: 10% reduction
        } else {
            80   // High velocity: 20% reduction
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // TREASURY BURN EXECUTION (13.15.5)
    // ════════════════════════════════════════════════════════════════════════════
    //
    // Execute actual treasury burn. This method:
    // - Checks burn eligibility (should_burn)
    // - Calculates adaptive burn rate
    // - Calculates burn amount
    // - Deducts from treasury_balance
    // - Updates total_supply
    // - Updates cumulative_burned
    // - Updates last_burn_epoch
    // - Records BurnEvent for audit
    //
    // CONSENSUS-CRITICAL: Deterministik, no side effects selain state update.
    // INI ADALAH SATU-SATUNYA TEMPAT DI MANA TOKEN DIMUSNAHKAN.
    //
    // ════════════════════════════════════════════════════════════════════════════

    /// Execute treasury burn for given epoch
    ///
    /// # Arguments
    /// * `current_epoch` - Epoch saat eksekusi burn
    /// * `timestamp` - Timestamp block (untuk BurnEvent)
    ///
    /// # Returns
    /// - `Some(BurnEvent)` jika burn berhasil dilakukan
    /// - `None` jika kondisi burn tidak terpenuhi atau amount = 0
    ///
    /// # Behavior (URUTAN TIDAK BOLEH DIUBAH)
    /// 1. Jika should_burn(current_epoch) == false → return None
    /// 2. Hitung rate = calculate_target_burn_rate()
    /// 3. Hitung amount = calculate_burn_amount(rate)
    /// 4. Jika amount == 0 → return None
    /// 5. Simpan snapshot: treasury_before, total_supply_before
    /// 6. Eksekusi burn:
    ///    - treasury_balance -= amount
    ///    - total_supply -= amount
    ///    - cumulative_burned += amount
    ///    - last_burn_epoch = current_epoch
    /// 7. Buat BurnEvent LENGKAP
    /// 8. Push event ke economic_events
    /// 9. Return Some(event)
    ///
    /// # Consensus-Critical
    /// - Integer-only arithmetic
    /// - Overflow-safe (saturating ops)
    /// - No panic
    /// - Deterministik di semua node
    /// - Tidak boleh burn di luar jadwal
    /// - Tidak boleh mengubah state jika gagal
    pub fn execute_treasury_burn(&mut self, current_epoch: u64, timestamp: u64) -> Option<BurnEvent> {
        // Step 1: Check should_burn - return None jika tidak eligible
        if !self.should_burn(current_epoch) {
            return None;
        }

        // Step 2: Calculate target burn rate
        let rate = self.calculate_target_burn_rate();

        // Step 3: Calculate burn amount
        let amount = self.calculate_burn_amount(rate);

        // Step 4: Check amount - return None jika 0
        if amount == 0 {
            return None;
        }

        // Step 5: Capture snapshot BEFORE any state changes
        let treasury_before = self.treasury_balance;
        let total_supply_before = self.total_supply;

        // Step 6: Execute burn (state mutations - URUTAN TIDAK BOLEH DIUBAH)
        // 6a: Deduct from treasury_balance (saturating to prevent underflow)
        self.treasury_balance = self.treasury_balance.saturating_sub(amount);

        // 6b: Reduce total_supply (burn = permanent removal from circulation)
        self.total_supply = self.total_supply.saturating_sub(amount);

        // 6c: Add to cumulative_burned (saturating to prevent overflow)
        self.cumulative_burned = self.cumulative_burned.saturating_add(amount);

        // 6d: Update last_burn_epoch
        self.last_burn_epoch = current_epoch;

        // Step 7: Create BurnEvent with full audit trail
        let event = BurnEvent {
            epoch: current_epoch,
            amount_burned: amount,
            burn_rate_applied: rate,
            total_supply_before,
            total_supply_after: self.total_supply,
            treasury_before,
            treasury_after: self.treasury_balance,
            timestamp,
        };

        // Step 8: Push event to economic_events for audit trail
        self.economic_events.push(event.clone());

        // Step 9: Return Some(event)
        Some(event)
    }

    /// Low-level burn from treasury (for testing / manual operations)
    ///
    /// # Arguments
    /// * `amount` - Jumlah token yang akan di-burn
    ///
    /// # Returns
    /// - `Ok(())` jika burn berhasil
    /// - `Err(EconomicError)` jika gagal
    ///
    /// # Behavior
    /// 1. Jika amount == 0 → Err(InvalidAmount)
    /// 2. Jika treasury_balance < amount → Err(InsufficientTreasury)
    /// 3. treasury_balance -= amount
    /// 4. total_supply -= amount
    /// 5. cumulative_burned += amount
    /// 6. Return Ok(())
    ///
    /// # Note
    /// - TIDAK update last_burn_epoch
    /// - TIDAK create BurnEvent
    /// - Digunakan untuk testing / manual burn operations
    ///
    /// # Consensus-Critical
    /// - Integer-only arithmetic
    /// - No panic
    /// - Deterministik
    pub fn burn_from_treasury(&mut self, amount: u128) -> Result<(), EconomicError> {
        // Step 1: Validate amount != 0
        if amount == 0 {
            return Err(EconomicError::InvalidAmount);
        }

        // Step 2: Validate treasury has sufficient balance
        if self.treasury_balance < amount {
            return Err(EconomicError::InsufficientTreasury);
        }

        // Step 3: Deduct from treasury_balance
        // Using checked_sub for extra safety, but we already validated
        self.treasury_balance = self.treasury_balance.saturating_sub(amount);

        // Step 4: Reduce total_supply
        self.total_supply = self.total_supply.saturating_sub(amount);

        // Step 5: Add to cumulative_burned
        self.cumulative_burned = self.cumulative_burned.saturating_add(amount);

        // Step 6: Return Ok
        Ok(())
    }

    /// Get annual burn rate in basis points
    ///
    /// # Returns
    /// Annual burn rate dalam basis points (10000 = 100%)
    /// Returns 0 jika belum ada burn
    ///
    /// # Formula
    /// ```text
    /// annual_rate = (cumulative_burned * 10000) / total_supply
    /// ```
    ///
    /// # Consensus-Critical
    /// - Deterministik
    /// - Integer-only arithmetic
    /// - No panic
    pub fn get_annual_burn_rate(&self) -> u128 {
        // Step 1: Jika belum ada burn → return 0
        if self.cumulative_burned == 0 {
            return 0;
        }

        // Step 2: Prevent division by zero
        if self.total_supply == 0 {
            return 0;
        }

        // Step 3: Calculate annual rate in basis points
        // annual_rate = (cumulative_burned * 10000) / total_supply
        let annual_rate = self.cumulative_burned
            .saturating_mul(10_000)
            .checked_div(self.total_supply)
            .unwrap_or(0);

        annual_rate
    }

    /// Get burn history (all recorded burn events)
    ///
    /// # Returns
    /// Reference to the economic_events slice containing all BurnEvents
    ///
    /// # Behavior
    /// - Read-only access
    /// - Tidak clone
    /// - Tidak mutate
    ///
    /// # Note
    /// Digunakan untuk audit trail dan historical analysis
    pub fn get_burn_history(&self) -> &[BurnEvent] {
        &self.economic_events
    }

    // ════════════════════════════════════════════════════════════════════════════
    // BLOCK-LEVEL ECONOMIC JOB (13.15.6)
    // ════════════════════════════════════════════════════════════════════════════
    //
    // Entry point untuk economic processing per block.
    // WAJIB dipanggil setelah slashing, SEBELUM state_root.
    //
    // CONSENSUS-CRITICAL:
    // - Dijalankan di TITIK YANG SAMA di setiap node
    // - Urutan eksekusi TIDAK BOLEH berubah
    // - Hasil HARUS deterministik
    //
    // ════════════════════════════════════════════════════════════════════════════


    /// Process economic job untuk block
    ///
    /// # Arguments
    /// * `block_height` - Tinggi block saat ini
    /// * `timestamp` - Timestamp block
    ///
    /// # Returns
    /// - `Some(BurnEvent)` jika burn terjadi
    /// - `None` jika tidak ada burn
    ///
    /// # Execution Order (TIDAK BOLEH DIUBAH)
    /// 1. Update active counts
    /// 2. Check epoch transition → reset_epoch_metrics
    /// 3. Check burn eligibility
    /// 4. Execute burn jika eligible
    ///
    /// # Consensus-Critical
    /// - TIDAK memanggil compute_state_root
    /// - TIDAK mutate state selain ekonomi
    /// - TIDAK panic
    /// - TIDAK logging
    pub fn process_economic_job(
        &mut self,
        _block_height: u64,
        timestamp: u64,
    ) -> Option<BurnEvent> {
        // ─────────────────────────────────────────────────────────────
        // 1) UPDATE ACTIVE COUNTS
        // ─────────────────────────────────────────────────────────────
        self.update_active_counts();

        // ─────────────────────────────────────────────────────────────
        // 2) CHECK EPOCH TRANSITION
        // ─────────────────────────────────────────────────────────────
        // Epoch dihitung dari epoch_info.epoch_number yang dikelola oleh
        // epoch rotation logic. Epoch transition di-handle oleh caller.
        // Di sini kita hanya menggunakan epoch_info.epoch_number yang sudah
        // diupdate oleh epoch rotation sebelum economic job.
        let current_epoch = self.epoch_info.epoch_number;
        
        // Cek apakah epoch berubah dari last_updated_epoch
        // Jika berubah, reset epoch metrics
        if current_epoch > self.economic_metrics.last_updated_epoch {
            self.reset_epoch_metrics(current_epoch);
        }

        // ─────────────────────────────────────────────────────────────
        // 3) EXECUTE BURN (eligibility check internal)
        // ─────────────────────────────────────────────────────────────
        // execute_treasury_burn sudah meng-handle:
        // - should_burn() check
        // - amount == 0 check
        // - state mutations
        // - event recording ke economic_events
        // Returns None jika tidak eligible atau amount = 0
        self.execute_treasury_burn(current_epoch, timestamp)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ════════════════════════════════════════════════════════════════════════
    // EXISTING TESTS (13.15.3)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_update_replication_factor_bootstrap() {
        let mut state = ChainState::new();
        
        // Initially RF = BOOTSTRAP_RF (3), mode = Bootstrap
        assert_eq!(state.economic_metrics.replication_factor, BOOTSTRAP_RF);
        assert_eq!(state.deflation_config.mode, EconomicMode::Bootstrap);
        
        // Update RF to 3 (still bootstrap)
        state.update_replication_factor(3);
        assert_eq!(state.economic_metrics.replication_factor, 3);
        assert_eq!(state.deflation_config.mode, EconomicMode::Bootstrap);
    }

    #[test]
    fn test_update_replication_factor_active_transition() {
        let mut state = ChainState::new();
        
        // Update RF to 5 (> BOOTSTRAP_RF)
        state.update_replication_factor(5);
        
        assert_eq!(state.economic_metrics.replication_factor, 5);
        assert_eq!(state.deflation_config.mode, EconomicMode::Active);
    }

    #[test]
    fn test_update_replication_factor_disabled() {
        let mut state = ChainState::new();
        state.deflation_config.enabled = false;
        
        // Update RF to 5, but deflation disabled
        state.update_replication_factor(5);
        
        assert_eq!(state.economic_metrics.replication_factor, 5);
        // Mode should remain Bootstrap because deflation is disabled
        assert_eq!(state.deflation_config.mode, EconomicMode::Bootstrap);
    }

    #[test]
    fn test_record_storage_usage() {
        let mut state = ChainState::new();
        
        assert_eq!(state.economic_metrics.storage_usage_bytes, 0);
        
        state.record_storage_usage(1000);
        assert_eq!(state.economic_metrics.storage_usage_bytes, 1000);
        
        state.record_storage_usage(500);
        assert_eq!(state.economic_metrics.storage_usage_bytes, 1500);
    }

    #[test]
    fn test_record_storage_usage_overflow_safe() {
        let mut state = ChainState::new();
        state.economic_metrics.storage_usage_bytes = u128::MAX - 10;
        
        // Should not panic, saturates at MAX
        state.record_storage_usage(100);
        assert_eq!(state.economic_metrics.storage_usage_bytes, u128::MAX);
    }

    #[test]
    fn test_record_compute_usage() {
        let mut state = ChainState::new();
        
        assert_eq!(state.economic_metrics.compute_cycles_used, 0);
        
        state.record_compute_usage(5000);
        assert_eq!(state.economic_metrics.compute_cycles_used, 5000);
        
        state.record_compute_usage(3000);
        assert_eq!(state.economic_metrics.compute_cycles_used, 8000);
    }

    #[test]
    fn test_update_token_velocity_initial() {
        let mut state = ChainState::new();
        
        // Initial velocity is 0
        assert_eq!(state.economic_metrics.token_velocity, 0);
        
        // Transfer volume = 10000
        state.update_token_velocity(10000, 1);
        
        // EMA: (80 * 10000 + 20 * 0) / 100 = 8000
        assert_eq!(state.economic_metrics.token_velocity, 8000);
        assert_eq!(state.economic_metrics.last_updated_epoch, 1);
    }

    #[test]
    fn test_update_token_velocity_ema() {
        let mut state = ChainState::new();
        
        // First update
        state.update_token_velocity(10000, 1);
        let _v1 = state.economic_metrics.token_velocity; // 8000
        
        // Second update with same volume
        state.update_token_velocity(10000, 2);
        let v2 = state.economic_metrics.token_velocity;
        
        // EMA: (80 * 10000 + 20 * 8000) / 100 = 9600
        assert_eq!(v2, 9600);
        
        // Third update
        state.update_token_velocity(10000, 3);
        let v3 = state.economic_metrics.token_velocity;
        
        // EMA: (80 * 10000 + 20 * 9600) / 100 = 9920
        assert_eq!(v3, 9920);
    }

    #[test]
    fn test_record_treasury_inflow_fee() {
        let mut state = ChainState::new();
        
        assert_eq!(state.economic_metrics.treasury_inflow_epoch, 0);
        
        state.record_treasury_inflow(1000, "fee");
        assert_eq!(state.economic_metrics.treasury_inflow_epoch, 1000);
        
        state.record_treasury_inflow(500, "fee");
        assert_eq!(state.economic_metrics.treasury_inflow_epoch, 1500);
    }

    #[test]
    fn test_record_treasury_inflow_slashing() {
        let mut state = ChainState::new();
        
        assert_eq!(state.economic_metrics.slashing_inflow_epoch, 0);
        
        state.record_treasury_inflow(2000, "slashing");
        assert_eq!(state.economic_metrics.slashing_inflow_epoch, 2000);
    }

    #[test]
    fn test_record_treasury_inflow_unknown_source() {
        let mut state = ChainState::new();
        
        // Unknown source should be ignored, no panic
        state.record_treasury_inflow(1000, "unknown");
        state.record_treasury_inflow(1000, "reward");
        state.record_treasury_inflow(1000, "");
        
        // Both inflow counters should remain 0
        assert_eq!(state.economic_metrics.treasury_inflow_epoch, 0);
        assert_eq!(state.economic_metrics.slashing_inflow_epoch, 0);
    }

    #[test]
    fn test_reset_epoch_metrics() {
        let mut state = ChainState::new();
        
        // Set some values
        state.economic_metrics.treasury_inflow_epoch = 5000;
        state.economic_metrics.slashing_inflow_epoch = 2000;
        state.economic_metrics.last_updated_epoch = 10;
        
        // Reset
        state.reset_epoch_metrics(11);
        
        assert_eq!(state.economic_metrics.treasury_inflow_epoch, 0);
        assert_eq!(state.economic_metrics.slashing_inflow_epoch, 0);
        assert_eq!(state.economic_metrics.last_updated_epoch, 11);
    }

    #[test]
    fn test_get_economic_mode_disabled() {
        let mut state = ChainState::new();
        state.deflation_config.enabled = false;
        state.economic_metrics.replication_factor = 10;
        
        assert_eq!(state.get_economic_mode(), EconomicMode::Bootstrap);
    }

    #[test]
    fn test_get_economic_mode_governance() {
        let mut state = ChainState::new();
        state.deflation_config.mode = EconomicMode::Governance;
        
        assert_eq!(state.get_economic_mode(), EconomicMode::Governance);
    }

    #[test]
    fn test_get_economic_mode_active() {
        let mut state = ChainState::new();
        state.economic_metrics.replication_factor = 5; // > BOOTSTRAP_RF (3)
        
        assert_eq!(state.get_economic_mode(), EconomicMode::Active);
    }

    #[test]
    fn test_get_economic_mode_bootstrap() {
        let mut state = ChainState::new();
        state.economic_metrics.replication_factor = 3; // == BOOTSTRAP_RF
        
        assert_eq!(state.get_economic_mode(), EconomicMode::Bootstrap);
    }

    #[test]
    fn test_update_active_counts_empty() {
        let mut state = ChainState::new();
        
        // Empty maps should not panic
        state.update_active_counts();
        
        assert_eq!(state.economic_metrics.active_nodes, 0);
        assert_eq!(state.economic_metrics.active_validators, 0);
    }

    #[test]
    fn test_get_economic_snapshot() {
        let mut state = ChainState::new();
        
        // Setup some state
        state.treasury_balance = 10_000_000;
        state.total_supply = 1_000_000_000;
        state.cumulative_burned = 5_000_000;
        state.economic_metrics.replication_factor = 5;
        state.epoch_info.epoch_number = 100;
        
        let snapshot = state.get_economic_snapshot();
        
        assert_eq!(snapshot.epoch, 100);
        assert_eq!(snapshot.treasury_balance, 10_000_000);
        assert_eq!(snapshot.total_supply, 1_000_000_000);
        assert_eq!(snapshot.metrics.replication_factor, 5);
        
        // annual_burn_rate = (5_000_000 * 10000) / 1_000_000_000 = 50 basis points
        assert_eq!(snapshot.annual_burn_rate, 50);
    }

    #[test]
    fn test_get_economic_snapshot_zero_supply() {
        let mut state = ChainState::new();
        state.total_supply = 0;
        
        let snapshot = state.get_economic_snapshot();
        
        // Should not panic, annual_burn_rate = 0
        assert_eq!(snapshot.annual_burn_rate, 0);
    }

    #[test]
    fn test_velocity_smoothing_factor_value() {
        // Verify VELOCITY_SMOOTHING_FACTOR is 80 as per spec
        assert_eq!(VELOCITY_SMOOTHING_FACTOR, 80);
    }

    #[test]
    fn test_bootstrap_rf_value() {
        // Verify BOOTSTRAP_RF is 3 as per spec
        assert_eq!(BOOTSTRAP_RF, 3);
    }

    // ════════════════════════════════════════════════════════════════════════
    // NEW TESTS (13.15.4) - BURN RATE CALCULATION
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_calculate_target_burn_rate_bootstrap_mode() {
        let mut state = ChainState::new();
        // Default is Bootstrap mode (RF = 3)
        state.treasury_balance = 10_000_000;
        state.total_supply = 1_000_000_000;
        
        // Bootstrap mode should return 0
        let rate = state.calculate_target_burn_rate();
        assert_eq!(rate, 0);
    }

    #[test]
    fn test_calculate_target_burn_rate_low_treasury() {
        let mut state = ChainState::new();
        state.economic_metrics.replication_factor = 5;
        state.deflation_config.mode = EconomicMode::Active;
        state.treasury_balance = MIN_TREASURY_RESERVE - 1; // Below minimum
        state.total_supply = 1_000_000_000;
        
        // Low treasury should return 0
        let rate = state.calculate_target_burn_rate();
        assert_eq!(rate, 0);
    }

    #[test]
    fn test_calculate_target_burn_rate_active_mode() {
        let mut state = ChainState::new();
        state.economic_metrics.replication_factor = 5;
        state.deflation_config.mode = EconomicMode::Active;
        state.treasury_balance = 10_000_000;
        state.total_supply = 1_000_000_000;
        state.economic_metrics.token_velocity = 500_000; // Low velocity
        
        let rate = state.calculate_target_burn_rate();
        
        // Base rate = (300 + 600) / 2 = 450
        // RF=5 multiplier = 140
        // Velocity factor = 100 (low velocity)
        // adjusted = 450 * 140 / 100 = 630
        // adjusted = 630 * 100 / 100 = 630
        // Treasury ratio = 10_000_000 / 1_000_000 = 10 → +50
        // final = 680, but clamped to 600 (max)
        assert_eq!(rate, DEFLATION_TARGET_MAX_PERCENT);
    }

    #[test]
    fn test_calculate_target_burn_rate_high_velocity() {
        let mut state = ChainState::new();
        state.economic_metrics.replication_factor = 4;
        state.deflation_config.mode = EconomicMode::Active;
        state.treasury_balance = 2_000_000;
        state.total_supply = 1_000_000_000;
        state.economic_metrics.token_velocity = 15_000_000; // High velocity
        
        let rate = state.calculate_target_burn_rate();
        
        // Base rate = 450
        // RF=4 multiplier = 120
        // Velocity factor = 80 (high velocity)
        // adjusted = 450 * 120 / 100 = 540
        // adjusted = 540 * 80 / 100 = 432
        // Treasury ratio = 2 → no adjustment
        // final = 432, clamped to 432 (in range)
        assert!(rate >= DEFLATION_TARGET_MIN_PERCENT && rate <= DEFLATION_TARGET_MAX_PERCENT);
        assert_eq!(rate, 432);
    }

    #[test]
    fn test_calculate_burn_amount_basic() {
        let mut state = ChainState::new();
        state.total_supply = 1_000_000_000;
        state.treasury_balance = 100_000_000;
        
        // Rate = 450 basis points (4.5%)
        let amount = state.calculate_burn_amount(450);
        
        // annual_burn = 1_000_000_000 * 450 / 10000 = 45_000_000
        // epoch_burn = 45_000_000 / 365 = 123_287
        // max_burn_per_epoch = 1_000_000_000 * 50 / 10000 = 5_000_000
        // available = 100_000_000 - 1_000_000 = 99_000_000
        // final = min(123_287, 5_000_000, 99_000_000) = 123_287
        assert_eq!(amount, 123287);
    }

    #[test]
    fn test_calculate_burn_amount_limited_by_treasury() {
        let mut state = ChainState::new();
        state.total_supply = 1_000_000_000;
        state.treasury_balance = MIN_TREASURY_RESERVE + 50_000; // Only 50K available
        
        let amount = state.calculate_burn_amount(450);
        
        // Should be limited by treasury: 50_000
        assert_eq!(amount, 50_000);
    }

    #[test]
    fn test_calculate_burn_amount_limited_by_max_per_epoch() {
        let mut state = ChainState::new();
        state.total_supply = 100_000_000_000; // Very large supply
        state.treasury_balance = 50_000_000_000; // Very large treasury
        
        let amount = state.calculate_burn_amount(600); // Max rate
        
        // max_burn_per_epoch = 100_000_000_000 * 50 / 10000 = 500_000_000
        // This should be the limit
        let max_per_epoch = state.total_supply * MAX_BURN_PER_EPOCH_PERCENT / 10_000;
        assert!(amount <= max_per_epoch);
    }

    #[test]
    fn test_calculate_burn_amount_zero_rate() {
        let mut state = ChainState::new();
        state.total_supply = 1_000_000_000;
        state.treasury_balance = 100_000_000;
        
        let amount = state.calculate_burn_amount(0);
        assert_eq!(amount, 0);
    }

    #[test]
    fn test_calculate_burn_amount_zero_supply() {
        let mut state = ChainState::new();
        state.total_supply = 0;
        state.treasury_balance = 100_000_000;
        
        let amount = state.calculate_burn_amount(450);
        assert_eq!(amount, 0);
    }

    #[test]
    fn test_should_burn_all_conditions_met() {
        let mut state = ChainState::new();
        state.deflation_config.enabled = true;
        state.economic_metrics.replication_factor = 5;
        state.deflation_config.mode = EconomicMode::Active;
        state.treasury_balance = 10_000_000;
        state.last_burn_epoch = 0;
        state.deflation_config.burn_interval_epochs = 52;
        
        // Epoch 52 should allow burn
        assert!(state.should_burn(52));
        assert!(state.should_burn(100));
    }

    #[test]
    fn test_should_burn_disabled() {
        let mut state = ChainState::new();
        state.deflation_config.enabled = false;
        state.economic_metrics.replication_factor = 5;
        state.treasury_balance = 10_000_000;
        
        assert!(!state.should_burn(100));
    }

    #[test]
    fn test_should_burn_bootstrap_mode() {
        let mut state = ChainState::new();
        state.deflation_config.enabled = true;
        state.economic_metrics.replication_factor = 3; // Bootstrap
        state.treasury_balance = 10_000_000;
        
        assert!(!state.should_burn(100));
    }

    #[test]
    fn test_should_burn_interval_not_passed() {
        let mut state = ChainState::new();
        state.deflation_config.enabled = true;
        state.economic_metrics.replication_factor = 5;
        state.deflation_config.mode = EconomicMode::Active;
        state.treasury_balance = 10_000_000;
        state.last_burn_epoch = 50;
        state.deflation_config.burn_interval_epochs = 52;
        
        // Only 50 epochs since last burn, need 52
        assert!(!state.should_burn(100));
        
        // Exactly at interval
        assert!(state.should_burn(102));
    }

    #[test]
    fn test_should_burn_low_treasury() {
        let mut state = ChainState::new();
        state.deflation_config.enabled = true;
        state.economic_metrics.replication_factor = 5;
        state.deflation_config.mode = EconomicMode::Active;
        state.treasury_balance = MIN_TREASURY_RESERVE; // Equal to minimum
        state.last_burn_epoch = 0;
        
        assert!(!state.should_burn(100));
    }

    #[test]
    fn test_get_rf_multiplier_values() {
        let mut state = ChainState::new();
        
        state.economic_metrics.replication_factor = 3;
        assert_eq!(state.get_rf_multiplier(), 100);
        
        state.economic_metrics.replication_factor = 4;
        assert_eq!(state.get_rf_multiplier(), 120);
        
        state.economic_metrics.replication_factor = 5;
        assert_eq!(state.get_rf_multiplier(), 140);
        
        state.economic_metrics.replication_factor = 6;
        assert_eq!(state.get_rf_multiplier(), 160);
        
        state.economic_metrics.replication_factor = 10;
        assert_eq!(state.get_rf_multiplier(), 160);
    }

    #[test]
    fn test_get_velocity_factor_values() {
        let mut state = ChainState::new();
        
        // Low velocity
        state.economic_metrics.token_velocity = 500_000;
        assert_eq!(state.get_velocity_factor(), 100);
        
        // At low threshold
        state.economic_metrics.token_velocity = VELOCITY_THRESHOLD_LOW;
        assert_eq!(state.get_velocity_factor(), 90);
        
        // Medium velocity
        state.economic_metrics.token_velocity = 5_000_000;
        assert_eq!(state.get_velocity_factor(), 90);
        
        // At high threshold
        state.economic_metrics.token_velocity = VELOCITY_THRESHOLD_HIGH;
        assert_eq!(state.get_velocity_factor(), 80);
        
        // High velocity
        state.economic_metrics.token_velocity = 50_000_000;
        assert_eq!(state.get_velocity_factor(), 80);
    }

    #[test]
    fn test_burn_rate_constants() {
        // Verify constants match specification
        assert_eq!(DEFLATION_TARGET_MIN_PERCENT, 300);
        assert_eq!(DEFLATION_TARGET_MAX_PERCENT, 600);
        assert_eq!(MIN_TREASURY_RESERVE, 1_000_000);
        assert_eq!(MAX_BURN_PER_EPOCH_PERCENT, 50);
    }

    #[test]
    fn test_velocity_thresholds() {
        assert_eq!(VELOCITY_THRESHOLD_LOW, 1_000_000);
        assert_eq!(VELOCITY_THRESHOLD_HIGH, 10_000_000);
    }

    #[test]
    fn test_epochs_per_year() {
        assert_eq!(EPOCHS_PER_YEAR, 365);
    }

    #[test]
    fn test_calculate_burn_amount_no_overflow() {
        let mut state = ChainState::new();
        state.total_supply = u128::MAX / 2;
        state.treasury_balance = u128::MAX / 2;
        
        // Should not panic with large values
        let amount = state.calculate_burn_amount(600);
        
        // Should be clamped to max_burn_per_epoch or available treasury
        assert!(amount > 0);
    }

    #[test]
    fn test_calculate_target_burn_rate_clamp_to_min() {
        let mut state = ChainState::new();
        state.economic_metrics.replication_factor = 4;
        state.deflation_config.mode = EconomicMode::Active;
        state.treasury_balance = 1_100_000; // Just above minimum
        state.total_supply = 1_000_000_000;
        state.economic_metrics.token_velocity = 50_000_000; // Very high velocity
        
        let rate = state.calculate_target_burn_rate();
        
        // Should be clamped to minimum if calculated rate is too low
        assert!(rate >= DEFLATION_TARGET_MIN_PERCENT);
    }

    // ════════════════════════════════════════════════════════════════════════
    // TREASURY BURN EXECUTION TESTS (13.15.5)
    // ════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_economic_error_variants() {
        // Verify all error variants exist and are distinct
        let e1 = EconomicError::InsufficientTreasury;
        let e2 = EconomicError::BurnDisabled;
        let e3 = EconomicError::InvalidAmount;
        let e4 = EconomicError::NotYetDue;
        
        assert_ne!(e1, e2);
        assert_ne!(e2, e3);
        assert_ne!(e3, e4);
        assert_ne!(e1, e4);
    }

    #[test]
    fn test_execute_treasury_burn_should_burn_false() {
        let mut state = ChainState::new();
        // Deflation disabled → should_burn returns false
        state.deflation_config.enabled = false;
        state.treasury_balance = 100_000_000;
        
        let result = state.execute_treasury_burn(100, 1234567890);
        
        // Should return None when should_burn is false
        assert!(result.is_none());
        // State should not be modified
        assert_eq!(state.treasury_balance, 100_000_000);
    }

    #[test]
    fn test_execute_treasury_burn_amount_zero() {
        let mut state = ChainState::new();
        state.deflation_config.enabled = true;
        state.deflation_config.mode = EconomicMode::Active;
        state.economic_metrics.replication_factor = 5;
        // Treasury at minimum → calculate_burn_amount returns 0
        state.treasury_balance = MIN_TREASURY_RESERVE + 1;
        state.total_supply = 1;
        state.last_burn_epoch = 0;
        state.deflation_config.burn_interval_epochs = 1;
        
        let result = state.execute_treasury_burn(100, 1234567890);
        
        // May return None if amount is 0
        // State should not be modified if None
        if result.is_none() {
            assert_eq!(state.cumulative_burned, 0);
        }
    }

    #[test]
    fn test_execute_treasury_burn_success() {
        let mut state = ChainState::new();
        state.deflation_config.enabled = true;
        state.deflation_config.mode = EconomicMode::Active;
        state.economic_metrics.replication_factor = 5;
        state.treasury_balance = 100_000_000;
        state.total_supply = 1_000_000_000;
        state.last_burn_epoch = 0;
        state.deflation_config.burn_interval_epochs = 52;
        
        let treasury_before = state.treasury_balance;
        let supply_before = state.total_supply;
        
        let result = state.execute_treasury_burn(52, 1234567890);
        
        assert!(result.is_some());
        let event = result.unwrap();
        
        // Verify event fields
        assert_eq!(event.epoch, 52);
        assert!(event.amount_burned > 0);
        assert_eq!(event.total_supply_before, supply_before);
        assert_eq!(event.treasury_before, treasury_before);
        assert_eq!(event.timestamp, 1234567890);
        
        // Verify state was updated
        assert!(state.treasury_balance < treasury_before);
        assert!(state.total_supply < supply_before);
        assert!(state.cumulative_burned > 0);
        assert_eq!(state.last_burn_epoch, 52);
        
        // Verify event was pushed to economic_events
        assert_eq!(state.economic_events.len(), 1);
    }

    #[test]
    fn test_execute_treasury_burn_no_double_burn() {
        let mut state = ChainState::new();
        state.deflation_config.enabled = true;
        state.deflation_config.mode = EconomicMode::Active;
        state.economic_metrics.replication_factor = 5;
        state.treasury_balance = 100_000_000;
        state.total_supply = 1_000_000_000;
        state.last_burn_epoch = 0;
        state.deflation_config.burn_interval_epochs = 52;
        
        // First burn at epoch 52
        let result1 = state.execute_treasury_burn(52, 1000);
        assert!(result1.is_some());
        
        // Second burn attempt at epoch 52 should fail (same epoch)
        let result2 = state.execute_treasury_burn(52, 1001);
        assert!(result2.is_none());
        
        // Third burn attempt at epoch 53 should fail (interval not passed)
        let result3 = state.execute_treasury_burn(53, 1002);
        assert!(result3.is_none());
        
        // Only one event should be recorded
        assert_eq!(state.economic_events.len(), 1);
    }

    #[test]
    fn test_burn_from_treasury_success() {
        let mut state = ChainState::new();
        state.treasury_balance = 10_000_000;
        state.total_supply = 100_000_000;
        
        let result = state.burn_from_treasury(1_000_000);
        
        assert!(result.is_ok());
        assert_eq!(state.treasury_balance, 9_000_000);
        assert_eq!(state.total_supply, 99_000_000);
        assert_eq!(state.cumulative_burned, 1_000_000);
        // last_burn_epoch should NOT be updated
        assert_eq!(state.last_burn_epoch, 0);
        // economic_events should NOT be modified
        assert_eq!(state.economic_events.len(), 0);
    }

    #[test]
    fn test_burn_from_treasury_zero_amount() {
        let mut state = ChainState::new();
        state.treasury_balance = 10_000_000;
        
        let result = state.burn_from_treasury(0);
        
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), EconomicError::InvalidAmount);
        // State should not be modified
        assert_eq!(state.treasury_balance, 10_000_000);
    }

    #[test]
    fn test_burn_from_treasury_insufficient() {
        let mut state = ChainState::new();
        state.treasury_balance = 1_000_000;
        
        let result = state.burn_from_treasury(2_000_000);
        
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), EconomicError::InsufficientTreasury);
        // State should not be modified
        assert_eq!(state.treasury_balance, 1_000_000);
    }

    #[test]
    fn test_burn_from_treasury_exact_balance() {
        let mut state = ChainState::new();
        state.treasury_balance = 5_000_000;
        state.total_supply = 100_000_000;
        
        let result = state.burn_from_treasury(5_000_000);
        
        assert!(result.is_ok());
        assert_eq!(state.treasury_balance, 0);
        assert_eq!(state.total_supply, 95_000_000);
        assert_eq!(state.cumulative_burned, 5_000_000);
    }

    #[test]
    fn test_get_annual_burn_rate_no_burn() {
        let state = ChainState::new();
        
        let rate = state.get_annual_burn_rate();
        
        assert_eq!(rate, 0);
    }

    #[test]
    fn test_get_annual_burn_rate_with_burns() {
        let mut state = ChainState::new();
        state.total_supply = 100_000_000;
        state.cumulative_burned = 5_000_000; // 5% burned
        
        let rate = state.get_annual_burn_rate();
        
        // (5_000_000 * 10000) / 100_000_000 = 500 basis points
        assert_eq!(rate, 500);
    }

    #[test]
    fn test_get_annual_burn_rate_zero_supply() {
        let mut state = ChainState::new();
        state.total_supply = 0;
        state.cumulative_burned = 1_000_000;
        
        let rate = state.get_annual_burn_rate();
        
        // Should return 0 to avoid division by zero
        assert_eq!(rate, 0);
    }

    #[test]
    fn test_get_burn_history_empty() {
        let state = ChainState::new();
        
        let history = state.get_burn_history();
        
        assert!(history.is_empty());
    }

    #[test]
    fn test_get_burn_history_with_events() {
        let mut state = ChainState::new();
        state.deflation_config.enabled = true;
        state.deflation_config.mode = EconomicMode::Active;
        state.economic_metrics.replication_factor = 5;
        state.treasury_balance = 100_000_000;
        state.total_supply = 1_000_000_000;
        state.last_burn_epoch = 0;
        state.deflation_config.burn_interval_epochs = 52;
        
        // Execute burn
        let _ = state.execute_treasury_burn(52, 1000);
        
        let history = state.get_burn_history();
        
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].epoch, 52);
    }

    #[test]
    fn test_burn_state_consistency() {
        let mut state = ChainState::new();
        state.deflation_config.enabled = true;
        state.deflation_config.mode = EconomicMode::Active;
        state.economic_metrics.replication_factor = 5;
        state.treasury_balance = 100_000_000;
        state.total_supply = 1_000_000_000;
        state.last_burn_epoch = 0;
        state.deflation_config.burn_interval_epochs = 52;
        
        let initial_sum = state.treasury_balance + state.cumulative_burned;
        
        // Execute burn
        let result = state.execute_treasury_burn(52, 1000);
        assert!(result.is_some());
        let event = result.unwrap();
        
        // Verify consistency: treasury_before - amount = treasury_after
        assert_eq!(
            event.treasury_before - event.amount_burned,
            event.treasury_after
        );
        
        // Verify consistency: total_supply_before - amount = total_supply_after
        assert_eq!(
            event.total_supply_before - event.amount_burned,
            event.total_supply_after
        );
        
        // Verify: treasury + cumulative_burned should remain constant
        // (tokens are just moved from treasury to "burned" category)
        let final_sum = state.treasury_balance + state.cumulative_burned;
        assert_eq!(initial_sum, final_sum);
    }

    #[test]
    fn test_multiple_burns_sequential() {
        let mut state = ChainState::new();
        state.deflation_config.enabled = true;
        state.deflation_config.mode = EconomicMode::Active;
        state.economic_metrics.replication_factor = 5;
        state.treasury_balance = 100_000_000;
        state.total_supply = 1_000_000_000;
        state.last_burn_epoch = 0;
        state.deflation_config.burn_interval_epochs = 52;
        
        // First burn at epoch 52
        let result1 = state.execute_treasury_burn(52, 1000);
        assert!(result1.is_some());
        let burned1 = state.cumulative_burned;
        
        // Second burn at epoch 104 (52 + 52)
        let result2 = state.execute_treasury_burn(104, 2000);
        assert!(result2.is_some());
        let burned2 = state.cumulative_burned;
        
        // Cumulative burned should increase
        assert!(burned2 > burned1);
        
        // Should have two events
        assert_eq!(state.economic_events.len(), 2);
        assert_eq!(state.economic_events[0].epoch, 52);
        assert_eq!(state.economic_events[1].epoch, 104);
    }
}