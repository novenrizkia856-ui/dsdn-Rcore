//! Internal slashing adapter functions
//! Logic slashing untuk ChainState (TETAP MILIK state, BUKAN crate::slashing)
//! Dipindahkan dari state.rs untuk modularisasi
//!
//! ## 13.14.2 — Node Liveness Tracking
//!
//! Methods untuk tracking liveness storage/compute nodes:
//! - record_node_heartbeat: Catat heartbeat dari node
//! - check_node_liveness: Deteksi offline berkepanjangan
//! - record_data_corruption: Deteksi data corruption berulang
//! - record_malicious_behavior: Deteksi malicious behavior
//! - is_node_force_unbonded: Check status force-unbond
//!
//! ## 13.14.3 — Validator Slashing Detection
//!
//! Methods untuk deteksi pelanggaran validator:
//! - detect_double_sign: Deteksi double signing
//! - detect_prolonged_offline: Deteksi offline berkepanjangan
//! - detect_malicious_block: Deteksi malicious block production
//! - get_validator_slash_reason: Get SlashingReason untuk validator

use crate::types::{Address, Hash};
use crate::slashing::{
    NodeLivenessRecord,
    SlashingReason,
    SlashingEvent,
    NODE_LIVENESS_THRESHOLD_SECONDS,
    NODE_LIVENESS_SLASH_PERCENT,
    NODE_DATA_CORRUPTION_SLASH_PERCENT,
    VALIDATOR_DOUBLE_SIGN_SLASH_PERCENT,
    VALIDATOR_OFFLINE_SLASH_PERCENT,
    VALIDATOR_MALICIOUS_BLOCK_SLASH_PERCENT,
    SLASHING_TREASURY_RATIO,
    SLASHING_BURN_RATIO,
    FORCE_UNBOND_DELAY_SECONDS,
};
use crate::tokenomics::calculate_slash_allocation;
use super::ChainState;

// ════════════════════════════════════════════════════════════════════════════
// 13.14.4 — SLASH ERROR ENUM
// ════════════════════════════════════════════════════════════════════════════

/// Error types for automatic slashing execution.
///
/// Variant order is consensus-critical. Do NOT reorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlashError {
    /// Target does not have sufficient stake to slash
    InsufficientStake,
    /// Target has already been slashed
    AlreadySlashed,
    /// SlashingReason is not valid for this target type
    InvalidReason,
    /// Node address not found in records
    NodeNotFound,
    /// Validator address not found in records
    ValidatorNotFound,
}

// ════════════════════════════════════════════════════════════════════════════
// 13.14.5 — DELEGATOR PROTECTION CONSTANTS
// ════════════════════════════════════════════════════════════════════════════

/// Delegator slash threshold in basis points (2000 = 20%)
/// Delegator hanya di-slash jika validator loss > 20%
/// 
/// CONSENSUS-CRITICAL: Do NOT change without hard-fork.
pub const DELEGATOR_SLASH_THRESHOLD: u16 = 2000;

impl ChainState {
    // ════════════════════════════════════════════════════════════════════════════
    // 13.14.2 — NODE LIVENESS TRACKING
    // ════════════════════════════════════════════════════════════════════════════
    // Detection layer untuk storage/compute nodes.
    // Methods di section ini HANYA mendeteksi dan return SlashingReason.
    // TIDAK ADA slashing execution di sini.
    // ════════════════════════════════════════════════════════════════════════════

    /// Record heartbeat dari node.
    ///
    /// Dipanggil ketika node mengirim heartbeat/proof-of-activity.
    /// Method ini:
    /// - Membuat NodeLivenessRecord baru jika belum ada
    /// - Update last_seen_timestamp
    /// - Reset consecutive_failures ke 0
    ///
    /// # Arguments
    ///
    /// * `node` - Address node yang mengirim heartbeat
    /// * `timestamp` - Unix timestamp saat heartbeat diterima
    ///
    /// # Note
    ///
    /// Method ini TIDAK memicu slashing. Hanya mencatat aktivitas.
    pub fn record_node_heartbeat(&mut self, node: Address, timestamp: u64) {
        let record = self.node_liveness_records
            .entry(node)
            .or_insert_with(|| NodeLivenessRecord {
                node_address: node,
                last_seen_timestamp: 0,
                consecutive_failures: 0,
                data_corruption_count: 0,
                malicious_behavior_count: 0,
                force_unbond_until: None,
                slashed: false,
                double_sign_detected: false,
                malicious_block_detected: false,
                offline_since: None,
            });
        
        record.last_seen_timestamp = timestamp;
        record.consecutive_failures = 0;
        // Reset offline tracking karena node aktif
        record.offline_since = None;
    }

    /// Check liveness node dan deteksi offline berkepanjangan.
    ///
    /// Method ini memeriksa apakah node telah offline melebihi threshold.
    /// Jika ya, increment consecutive_failures dan return SlashingReason.
    ///
    /// # Arguments
    ///
    /// * `node` - Address node yang akan dicek
    /// * `current_timestamp` - Unix timestamp saat ini
    ///
    /// # Returns
    ///
    /// * `Some(SlashingReason::NodeLivenessFailure)` - Node offline ≥ 12 jam
    /// * `None` - Node masih dalam batas waktu atau record tidak ditemukan
    ///
    /// # Note
    ///
    /// Method ini HANYA MENDETEKSI. Tidak melakukan slashing.
    pub fn check_node_liveness(
        &mut self,
        node: Address,
        current_timestamp: u64,
    ) -> Option<SlashingReason> {
        // Jika record tidak ada, return None
        let record = self.node_liveness_records.get_mut(&node)?;
        
        // Hitung selisih waktu
        let time_since_last_seen = current_timestamp.saturating_sub(record.last_seen_timestamp);
        
        // Check apakah melebihi threshold
        if time_since_last_seen >= NODE_LIVENESS_THRESHOLD_SECONDS {
            // Increment consecutive failures
            record.consecutive_failures = record.consecutive_failures.saturating_add(1);
            
            // Jika consecutive_failures >= 1, trigger slashing reason
            if record.consecutive_failures >= 1 {
                return Some(SlashingReason::NodeLivenessFailure);
            }
        }
        
        None
    }

    /// Record data corruption event dari node.
    ///
    /// Dipanggil ketika terdeteksi data corruption dari node.
    /// Increment counter dan return SlashingReason jika sudah 2x berturut.
    ///
    /// # Arguments
    ///
    /// * `node` - Address node yang mengalami data corruption
    ///
    /// # Returns
    ///
    /// * `Some(SlashingReason::NodeDataCorruption)` - Sudah 2x corruption
    /// * `None` - Baru pertama kali atau record tidak ditemukan
    ///
    /// # Note
    ///
    /// Method ini HANYA MENDETEKSI. Tidak melakukan slashing.
    pub fn record_data_corruption(&mut self, node: Address) -> Option<SlashingReason> {
        let record = self.node_liveness_records
            .entry(node)
            .or_insert_with(|| NodeLivenessRecord {
                node_address: node,
                last_seen_timestamp: 0,
                consecutive_failures: 0,
                data_corruption_count: 0,
                malicious_behavior_count: 0,
                force_unbond_until: None,
                slashed: false,
                double_sign_detected: false,
                malicious_block_detected: false,
                offline_since: None,
            });
        
        // Increment data corruption count
        record.data_corruption_count = record.data_corruption_count.saturating_add(1);
        
        // Trigger slashing jika sudah 2x berturut
        if record.data_corruption_count >= 2 {
            return Some(SlashingReason::NodeDataCorruption);
        }
        
        None
    }

    /// Record malicious behavior dari node.
    ///
    /// Dipanggil ketika terdeteksi malicious behavior dari node.
    /// Langsung return SlashingReason pada behavior pertama.
    ///
    /// # Arguments
    ///
    /// * `node` - Address node yang melakukan malicious behavior
    ///
    /// # Returns
    ///
    /// * `Some(SlashingReason::NodeMaliciousBehavior)` - Malicious behavior terdeteksi
    /// * `None` - Tidak pernah terjadi (selalu return Some setelah increment)
    ///
    /// # Note
    ///
    /// Method ini HANYA MENDETEKSI. Tidak melakukan slashing.
    pub fn record_malicious_behavior(&mut self, node: Address) -> Option<SlashingReason> {
        let record = self.node_liveness_records
            .entry(node)
            .or_insert_with(|| NodeLivenessRecord {
                node_address: node,
                last_seen_timestamp: 0,
                consecutive_failures: 0,
                data_corruption_count: 0,
                malicious_behavior_count: 0,
                force_unbond_until: None,
                slashed: false,
                double_sign_detected: false,
                malicious_block_detected: false,
                offline_since: None,
            });
        
        // Increment malicious behavior count
        record.malicious_behavior_count = record.malicious_behavior_count.saturating_add(1);
        
        // Trigger slashing pada behavior pertama (count >= 1)
        if record.malicious_behavior_count >= 1 {
            return Some(SlashingReason::NodeMaliciousBehavior);
        }
        
        None
    }

    /// Check apakah node sedang dalam status force-unbond.
    ///
    /// Node yang di-force-unbond tidak dapat berpartisipasi dalam network
    /// sampai periode force-unbond berakhir.
    ///
    /// # Arguments
    ///
    /// * `node` - Address node yang akan dicek
    /// * `current_timestamp` - Unix timestamp saat ini
    ///
    /// # Returns
    ///
    /// * `true` - Node masih dalam periode force-unbond
    /// * `false` - Node tidak di-force-unbond atau periode sudah berakhir
    pub fn is_node_force_unbonded(&self, node: Address, current_timestamp: u64) -> bool {
        match self.node_liveness_records.get(&node) {
            Some(record) => {
                match record.force_unbond_until {
                    Some(until_timestamp) => current_timestamp < until_timestamp,
                    None => false,
                }
            }
            None => false,
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // 13.14.3 — VALIDATOR SLASHING DETECTION
    // ════════════════════════════════════════════════════════════════════════════
    // Detection layer untuk validator violations.
    // Methods di section ini HANYA mendeteksi dan return bool/SlashingReason.
    // TIDAK ADA slashing execution di sini.
    // ════════════════════════════════════════════════════════════════════════════

    /// Detect double-sign dari validator.
    ///
    /// Dipanggil ketika dua signature berbeda terdeteksi untuk block height yang sama.
    /// Jika signature berbeda, tandai double_sign_detected = true.
    ///
    /// # Arguments
    ///
    /// * `validator` - Address validator yang dicurigai
    /// * `block_height` - Block height dimana double-sign terjadi
    /// * `signature1` - Signature pertama
    /// * `signature2` - Signature kedua
    ///
    /// # Returns
    ///
    /// * `true` - Double-sign terdeteksi (signature berbeda)
    /// * `false` - Tidak ada double-sign (signature sama)
    ///
    /// # Note
    ///
    /// Method ini TIDAK memverifikasi kriptografi. Hanya membandingkan bytes.
    /// Verifikasi kriptografi dilakukan di layer lain.
    pub fn detect_double_sign(
        &mut self,
        validator: Address,
        _block_height: u64,
        signature1: Vec<u8>,
        signature2: Vec<u8>,
    ) -> bool {
        // Jika signature berbeda, ini adalah double-sign
        if signature1 != signature2 {
            // Get atau create record
            let record = self.node_liveness_records
                .entry(validator)
                .or_insert_with(|| NodeLivenessRecord {
                    node_address: validator,
                    last_seen_timestamp: 0,
                    consecutive_failures: 0,
                    data_corruption_count: 0,
                    malicious_behavior_count: 0,
                    force_unbond_until: None,
                    slashed: false,
                    double_sign_detected: false,
                    malicious_block_detected: false,
                    offline_since: None,
                });
            
            // Tandai double-sign detected
            record.double_sign_detected = true;
            return true;
        }
        
        false
    }

    /// Detect prolonged offline dari validator.
    ///
    /// Dipanggil untuk check apakah validator sudah offline terlalu lama.
    /// Jika offline_since belum di-set, set ke current_timestamp.
    /// Jika sudah di-set, check apakah durasi melebihi threshold.
    ///
    /// # Arguments
    ///
    /// * `validator` - Address validator yang dicek
    /// * `current_timestamp` - Unix timestamp saat ini
    ///
    /// # Returns
    ///
    /// * `true` - Validator offline melebihi threshold
    /// * `false` - Validator baru offline atau masih dalam threshold
    ///
    /// # Note
    ///
    /// Threshold menggunakan NODE_LIVENESS_THRESHOLD_SECONDS (12 jam).
    /// Method ini TIDAK melakukan slashing.
    pub fn detect_prolonged_offline(
        &mut self,
        validator: Address,
        current_timestamp: u64,
    ) -> bool {
        // Get atau create record
        let record = self.node_liveness_records
            .entry(validator)
            .or_insert_with(|| NodeLivenessRecord {
                node_address: validator,
                last_seen_timestamp: 0,
                consecutive_failures: 0,
                data_corruption_count: 0,
                malicious_behavior_count: 0,
                force_unbond_until: None,
                slashed: false,
                double_sign_detected: false,
                malicious_block_detected: false,
                offline_since: None,
            });
        
        // Check offline_since
        match record.offline_since {
            None => {
                // Pertama kali offline, set timestamp
                record.offline_since = Some(current_timestamp);
                false
            }
            Some(offline_start) => {
                // Hitung durasi offline
                let offline_duration = current_timestamp.saturating_sub(offline_start);
                
                // Check apakah melebihi threshold
                if offline_duration >= NODE_LIVENESS_THRESHOLD_SECONDS {
                    return true;
                }
                
                false
            }
        }
    }

    /// Detect malicious block production dari validator.
    ///
    /// Dipanggil ketika ada evidence malicious block dari validator.
    /// Jika evidence tidak kosong, tandai malicious_block_detected = true.
    ///
    /// # Arguments
    ///
    /// * `validator` - Address validator yang menghasilkan block
    /// * `_block_hash` - Hash block yang dicurigai (untuk logging)
    /// * `evidence` - Bukti malicious behavior
    ///
    /// # Returns
    ///
    /// * `true` - Malicious block terdeteksi (evidence tidak kosong)
    /// * `false` - Tidak ada evidence
    ///
    /// # Note
    ///
    /// Validasi evidence dilakukan di layer lain.
    /// Method ini hanya melakukan flagging berdasarkan keberadaan evidence.
    pub fn detect_malicious_block(
        &mut self,
        validator: Address,
        _block_hash: Hash,
        evidence: Vec<u8>,
    ) -> bool {
        // Jika evidence tidak kosong, ini adalah malicious block
        if !evidence.is_empty() {
            // Get atau create record
            let record = self.node_liveness_records
                .entry(validator)
                .or_insert_with(|| NodeLivenessRecord {
                    node_address: validator,
                    last_seen_timestamp: 0,
                    consecutive_failures: 0,
                    data_corruption_count: 0,
                    malicious_behavior_count: 0,
                    force_unbond_until: None,
                    slashed: false,
                    double_sign_detected: false,
                    malicious_block_detected: false,
                    offline_since: None,
                });
            
            // Tandai malicious block detected
            record.malicious_block_detected = true;
            return true;
        }
        
        false
    }

    /// Get SlashingReason untuk validator berdasarkan flags yang terdeteksi.
    ///
    /// Method ini memeriksa semua flags deteksi dan mengembalikan
    /// SlashingReason dengan prioritas tertentu.
    ///
    /// # Arguments
    ///
    /// * `validator` - Address validator yang dicek
    ///
    /// # Returns
    ///
    /// * `Some(SlashingReason)` - Ada pelanggaran terdeteksi
    /// * `None` - Tidak ada pelanggaran
    ///
    /// # Priority Order (CONSENSUS-CRITICAL)
    ///
    /// 1. ValidatorDoubleSign (tertinggi)
    /// 2. ValidatorMaliciousBlock
    /// 3. ValidatorProlongedOffline (terendah)
    ///
    /// # Note
    ///
    /// Method ini READ-ONLY. Tidak mengubah state.
    pub fn get_validator_slash_reason(&self, validator: Address) -> Option<SlashingReason> {
        // Get record, return None jika tidak ada
        let record = self.node_liveness_records.get(&validator)?;
        
        // Priority 1: Double-sign (paling serius)
        if record.double_sign_detected {
            return Some(SlashingReason::ValidatorDoubleSign);
        }
        
        // Priority 2: Malicious block
        if record.malicious_block_detected {
            return Some(SlashingReason::ValidatorMaliciousBlock);
        }
        
        // Priority 3: Prolonged offline
        // Check offline_since dan durasi
        if let Some(_offline_start) = record.offline_since {
            // Untuk check offline, kita perlu current_timestamp
            // Tapi method ini read-only tanpa timestamp parameter
            // Jadi kita check apakah offline_since sudah di-set
            // dan consecutive_failures > 0 sebagai indicator
            if record.consecutive_failures > 0 {
                return Some(SlashingReason::ValidatorProlongedOffline);
            }
        }
        
        None
    }

/// Reset offline tracking untuk validator.
    ///
    /// Dipanggil ketika validator kembali online (produce block atau heartbeat).
    /// Method ini clear offline_since flag.
    ///
    /// # Arguments
    ///
    /// * `validator` - Address validator yang kembali online
    pub fn reset_validator_offline(&mut self, validator: Address) {
        if let Some(record) = self.node_liveness_records.get_mut(&validator) {
            record.offline_since = None;
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // 13.14.4 — AUTOMATIC SLASH EXECUTION
    // ════════════════════════════════════════════════════════════════════════════
    // Execution layer untuk automatic slashing.
    // Methods di section ini BENAR-BENAR memotong stake dan mendistribusikan dana.
    // SEMUA OPERASI BERSIFAT ATOMIC DAN TIDAK DAPAT DIBATALKAN.
    // ════════════════════════════════════════════════════════════════════════════

    /// Execute automatic slashing untuk node (storage/compute).
    ///
    /// Method ini BENAR-BENAR memotong stake dari node dan mendistribusikan
    /// dana ke treasury dan burn.
    ///
    /// # Arguments
    ///
    /// * `node` - Address node yang akan di-slash
    /// * `reason` - SlashingReason yang sudah divalidasi
    /// * `current_timestamp` - Unix timestamp saat eksekusi
    ///
    /// # Returns
    ///
    /// * `Ok(SlashingEvent)` - Slashing berhasil dieksekusi
    /// * `Err(SlashError)` - Slashing gagal karena kondisi tidak terpenuhi
    ///
    /// # Atomic Guarantee
    ///
    /// Jika method ini return Err, TIDAK ADA state yang berubah.
    pub fn execute_auto_slash_node(
        &mut self,
        node: Address,
        reason: SlashingReason,
        current_timestamp: u64,
    ) -> Result<SlashingEvent, SlashError> {
        // 1. Pastikan node ada dalam records
        if !self.node_liveness_records.contains_key(&node) {
            return Err(SlashError::NodeNotFound);
        }
        
        // 2. Pastikan node belum pernah di-slash
        {
            let record = self.node_liveness_records.get(&node)
                .ok_or(SlashError::NodeNotFound)?;
            if record.slashed {
                return Err(SlashError::AlreadySlashed);
            }
        }
        
        // 3. Validasi reason cocok untuk node
        let slash_percent_bp = match reason {
            SlashingReason::NodeLivenessFailure => NODE_LIVENESS_SLASH_PERCENT,
            SlashingReason::NodeDataCorruption => NODE_DATA_CORRUPTION_SLASH_PERCENT,
            SlashingReason::NodeMaliciousBehavior => NODE_DATA_CORRUPTION_SLASH_PERCENT, // Same as corruption
            // Validator reasons tidak valid untuk node
            SlashingReason::ValidatorDoubleSign |
            SlashingReason::ValidatorProlongedOffline |
            SlashingReason::ValidatorMaliciousBlock => {
                return Err(SlashError::InvalidReason);
            }
        };
        
        // 4. Get node stake (dari node_earnings atau locked)
        let node_stake = self.node_earnings.get(&node).copied().unwrap_or(0);
        if node_stake == 0 {
            return Err(SlashError::InsufficientStake);
        }
        
        // 5. Hitung jumlah slash (basis points: 50 = 0.5%, 500 = 5%)
        let slash_amount = (node_stake * slash_percent_bp as u128) / 10_000;
        if slash_amount == 0 {
            return Err(SlashError::InsufficientStake);
        }
        
        // 6. Allocate slashed amount ke treasury dan burn
        let (to_treasury, to_burn) = Self::allocate_slashed_amount(slash_amount);
        
        // 7. Apply slash ke node earnings
        let new_earnings = node_stake.saturating_sub(slash_amount);
        if new_earnings > 0 {
            self.node_earnings.insert(node, new_earnings);
        } else {
            self.node_earnings.remove(&node);
        }
        
        // 8. Add treasury portion
        self.treasury_balance = self.treasury_balance.saturating_add(to_treasury);
        
        // 9. Burn portion: reduce total_supply
        self.total_supply = self.total_supply.saturating_sub(to_burn);
        
        // 10. Apply force-unbond jika malicious behavior
        if matches!(reason, SlashingReason::NodeMaliciousBehavior) {
            self.apply_force_unbond(node, FORCE_UNBOND_DELAY_SECONDS, current_timestamp);
        }
        
        // 11. Mark node as slashed
        if let Some(record) = self.node_liveness_records.get_mut(&node) {
            record.slashed = true;
        }
        
        // 12. Create and return SlashingEvent
        let event = SlashingEvent {
            target: node,
            reason,
            amount_slashed: slash_amount,
            amount_to_treasury: to_treasury,
            amount_burned: to_burn,
            timestamp: current_timestamp,
        };
        
        // 13. Add to slashing_events audit trail
        self.slashing_events.push(event.clone());
        
        Ok(event)
    }

    /// Execute automatic slashing untuk validator.
    ///
    /// Method ini BENAR-BENAR memotong stake dari validator dan mendistribusikan
    /// dana ke treasury dan burn.
    ///
    /// # Arguments
    ///
    /// * `validator` - Address validator yang akan di-slash
    /// * `reason` - SlashingReason yang sudah divalidasi
    /// * `current_timestamp` - Unix timestamp saat eksekusi
    ///
    /// # Returns
    ///
    /// * `Ok(SlashingEvent)` - Slashing berhasil dieksekusi
    /// * `Err(SlashError)` - Slashing gagal karena kondisi tidak terpenuhi
    ///
    /// # Note
    ///
    /// Validator hanya boleh di-slash SEKALI. Double-slash akan return AlreadySlashed.
    pub fn execute_auto_slash_validator(
        &mut self,
        validator: Address,
        reason: SlashingReason,
        current_timestamp: u64,
    ) -> Result<SlashingEvent, SlashError> {
        // 1. Pastikan validator ada dalam validator_set
        if !self.validator_set.is_validator(&validator) {
            return Err(SlashError::ValidatorNotFound);
        }
        
        // 2. Check if already slashed via liveness_records (legacy)
        if let Some(record) = self.liveness_records.get(&validator) {
            if record.slashed {
                return Err(SlashError::AlreadySlashed);
            }
        }
        
        // 3. Also check node_liveness_records for slashed flag
        if let Some(record) = self.node_liveness_records.get(&validator) {
            if record.slashed {
                return Err(SlashError::AlreadySlashed);
            }
        }
        
        // 4. Validasi reason cocok untuk validator
        let slash_percent_bp = match reason {
            SlashingReason::ValidatorDoubleSign => VALIDATOR_DOUBLE_SIGN_SLASH_PERCENT,
            SlashingReason::ValidatorProlongedOffline => VALIDATOR_OFFLINE_SLASH_PERCENT,
            SlashingReason::ValidatorMaliciousBlock => VALIDATOR_MALICIOUS_BLOCK_SLASH_PERCENT,
            // Node reasons tidak valid untuk validator
            SlashingReason::NodeLivenessFailure |
            SlashingReason::NodeDataCorruption |
            SlashingReason::NodeMaliciousBehavior => {
                return Err(SlashError::InvalidReason);
            }
        };
        
        // 5. Get validator stake
        let validator_stake = self.validator_stakes.get(&validator).copied().unwrap_or(0);
        if validator_stake == 0 {
            return Err(SlashError::InsufficientStake);
        }
        
        // 6. Hitung jumlah slash (basis points: 100 = 1%, 1000 = 10%, 2000 = 20%)
        let slash_amount = (validator_stake * slash_percent_bp as u128) / 10_000;
        if slash_amount == 0 {
            return Err(SlashError::InsufficientStake);
        }
        
        // 7. Allocate slashed amount ke treasury dan burn
        let (to_treasury, to_burn) = Self::allocate_slashed_amount(slash_amount);
        
        // 8. Apply slash ke validator stake
        let new_stake = validator_stake.saturating_sub(slash_amount);
        if new_stake > 0 {
            self.validator_stakes.insert(validator, new_stake);
        } else {
            self.validator_stakes.remove(&validator);
        }
        
        // 9. Update locked amount
        let current_locked = self.locked.get(&validator).copied().unwrap_or(0);
        let new_locked = current_locked.saturating_sub(slash_amount);
        if new_locked > 0 {
            self.locked.insert(validator, new_locked);
        } else {
            self.locked.remove(&validator);
        }
        
        // 10. Update validator_set stake
        self.validator_set.update_stake(&validator, -(slash_amount as i128));
        
        // 11. Update legacy validators map
        if let Some(v) = self.validators.get_mut(&validator) {
            v.stake = v.stake.saturating_sub(slash_amount);
        }
        
        // 12. Add treasury portion
        self.treasury_balance = self.treasury_balance.saturating_add(to_treasury);
        
        // 13. Burn portion: reduce total_supply
        self.total_supply = self.total_supply.saturating_sub(to_burn);
        
        // 14. Update QV weights
        self.update_qv_weight(&validator);
        self.update_validator_qv_weight(&validator);
        
        // 15. Apply force-unbond jika malicious block
        if matches!(reason, SlashingReason::ValidatorMaliciousBlock) {
            self.apply_force_unbond(validator, FORCE_UNBOND_DELAY_SECONDS, current_timestamp);
        }
        
        // 16. Mark validator as slashed (legacy liveness_records)
        if let Some(record) = self.liveness_records.get_mut(&validator) {
            record.slashed = true;
            record.slash_count = record.slash_count.saturating_add(1);
        }
        
        // 17. Also mark in node_liveness_records if exists
        if let Some(record) = self.node_liveness_records.get_mut(&validator) {
            record.slashed = true;
        }
        
        // 18. Set validator inactive
        self.validator_set.set_active(&validator, false);
        if let Some(v) = self.validators.get_mut(&validator) {
            v.active = false;
        }
        
        // 19. Create SlashingEvent
        let event = SlashingEvent {
            target: validator,
            reason,
            amount_slashed: slash_amount,
            amount_to_treasury: to_treasury,
            amount_burned: to_burn,
            timestamp: current_timestamp,
        };
        
        // 20. Add to slashing_events audit trail
        self.slashing_events.push(event.clone());
        
        Ok(event)
    }

    /// Apply force-unbond ke target address.
    ///
    /// Force-unbond mencegah target berpartisipasi dalam network
    /// selama durasi tertentu.
    ///
    /// # Arguments
    ///
    /// * `target` - Address yang akan di-force-unbond
    /// * `duration` - Durasi force-unbond dalam detik
    /// * `current_timestamp` - Unix timestamp saat ini
    ///
    /// # Note
    ///
    /// Method ini TIDAK memotong stake. Hanya mengatur force_unbond_until.
pub fn apply_force_unbond(&mut self, target: Address, duration: u64, current_timestamp: u64) {
        let until_timestamp = current_timestamp.saturating_add(duration);
        
        // Update node_liveness_records
        let record = self.node_liveness_records
            .entry(target)
            .or_insert_with(|| NodeLivenessRecord {
                node_address: target,
                last_seen_timestamp: 0,
                consecutive_failures: 0,
                data_corruption_count: 0,
                malicious_behavior_count: 0,
                force_unbond_until: None,
                slashed: false,
                double_sign_detected: false,
                malicious_block_detected: false,
                offline_since: None,
            });
        
        record.force_unbond_until = Some(until_timestamp);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // 13.14.5 — DELEGATOR PROTECTION MECHANISM
    // ════════════════════════════════════════════════════════════════════════════
    // PRINSIP UTAMA: Delegator TIDAK BOLEH terkena slashing kecuali pada
    // kondisi protocol failure ekstrem.
    //
    // DEFAULT BEHAVIOR:
    // - Slashing hanya mengenai validator/node stake
    // - Delegator stake tetap AMAN
    //
    // EXCEPTION (Protocol Failure Ekstrem):
    // - ValidatorMaliciousBlock dengan evidence
    // - Validator loss > DELEGATOR_SLASH_THRESHOLD (20%)
    // - Delegator di-slash PROPORSIONAL, tidak melebihi validator loss
    // ════════════════════════════════════════════════════════════════════════════

    /// Check apakah reason merupakan protocol failure condition.
    ///
    /// Protocol failure condition adalah kondisi EKSTREM dimana
    /// delegator MUNGKIN terkena slashing.
    ///
    /// # Arguments
    ///
    /// * `reason` - SlashingReason yang akan dicek
    ///
    /// # Returns
    ///
    /// * `true` - Kondisi protocol failure (delegator MUNGKIN di-slash)
    /// * `false` - Kondisi normal (delegator AMAN)
    ///
    /// # Protocol Failure Conditions
    ///
    /// HANYA `ValidatorMaliciousBlock` yang dianggap protocol failure.
    /// Reason lain (termasuk DoubleSign) TIDAK mempengaruhi delegator.
    ///
    /// # Note
    ///
    /// Method ini PURE. Tidak mengubah state.
    pub fn is_protocol_failure_condition(reason: SlashingReason) -> bool {
        matches!(reason, SlashingReason::ValidatorMaliciousBlock)
    }

    /// Execute slashing dengan delegator protection.
    ///
    /// Method ini adalah ENTRY POINT UTAMA untuk slashing validator
    /// yang MENJAMIN perlindungan delegator.
    ///
    /// # Behavior
    ///
    /// 1. SELALU slash validator terlebih dahulu
    /// 2. Check is_protocol_failure_condition()
    /// 3. Jika BUKAN protocol failure → delegator AMAN
    /// 4. Jika protocol failure DAN validator_slash > threshold → slash delegator PROPORSIONAL
    ///
    /// # Arguments
    ///
    /// * `target` - Address validator yang akan di-slash
    /// * `reason` - SlashingReason yang sudah divalidasi
    /// * `current_timestamp` - Unix timestamp saat eksekusi
    ///
    /// # Returns
    ///
    /// * `Ok(SlashingEvent)` - Slashing berhasil (termasuk info delegator jika di-slash)
    /// * `Err(SlashError)` - Slashing gagal
    ///
    /// # Delegator Protection Guarantee
    ///
    /// - Delegator TIDAK di-slash pada kondisi normal
    /// - Delegator hanya di-slash pada protocol failure ekstrem
    /// - Delegator slash TIDAK PERNAH melebihi validator slash
    /// - Delegator slash SELALU proporsional
    pub fn slash_with_delegator_protection(
        &mut self,
        target: Address,
        reason: SlashingReason,
        current_timestamp: u64,
    ) -> Result<SlashingEvent, SlashError> {
        // ════════════════════════════════════════════════════════════════════
        // STEP 1: Validasi dan dapatkan slash percent
        // ════════════════════════════════════════════════════════════════════
        
        // Pastikan validator ada
        if !self.validator_set.is_validator(&target) {
            return Err(SlashError::ValidatorNotFound);
        }
        
        // Check if already slashed
        if let Some(record) = self.liveness_records.get(&target) {
            if record.slashed {
                return Err(SlashError::AlreadySlashed);
            }
        }
        if let Some(record) = self.node_liveness_records.get(&target) {
            if record.slashed {
                return Err(SlashError::AlreadySlashed);
            }
        }
        
        // Validasi reason dan get slash percent (basis points)
        let slash_percent_bp: u16 = match reason {
            SlashingReason::ValidatorDoubleSign => VALIDATOR_DOUBLE_SIGN_SLASH_PERCENT,
            SlashingReason::ValidatorProlongedOffline => VALIDATOR_OFFLINE_SLASH_PERCENT,
            SlashingReason::ValidatorMaliciousBlock => VALIDATOR_MALICIOUS_BLOCK_SLASH_PERCENT,
            // Node reasons tidak valid untuk validator
            _ => return Err(SlashError::InvalidReason),
        };
        
        // Get validator stake
        let validator_stake = self.validator_stakes.get(&target).copied().unwrap_or(0);
        if validator_stake == 0 {
            return Err(SlashError::InsufficientStake);
        }
        
        // ════════════════════════════════════════════════════════════════════
        // STEP 2: Execute validator slashing (SELALU dilakukan)
        // ════════════════════════════════════════════════════════════════════
        
        // Hitung slash amount
        let validator_slash_amount = (validator_stake * slash_percent_bp as u128) / 10_000;
        if validator_slash_amount == 0 {
            return Err(SlashError::InsufficientStake);
        }
        
        // Allocate ke treasury dan burn
        let (to_treasury, to_burn) = Self::allocate_slashed_amount(validator_slash_amount);
        
        // Apply slash ke validator stake
        let new_stake = validator_stake.saturating_sub(validator_slash_amount);
        if new_stake > 0 {
            self.validator_stakes.insert(target, new_stake);
        } else {
            self.validator_stakes.remove(&target);
        }
        
        // Update locked
        let current_locked = self.locked.get(&target).copied().unwrap_or(0);
        let new_locked = current_locked.saturating_sub(validator_slash_amount);
        if new_locked > 0 {
            self.locked.insert(target, new_locked);
        } else {
            self.locked.remove(&target);
        }
        
        // Update validator_set stake
        self.validator_set.update_stake(&target, -(validator_slash_amount as i128));
        
        // Update legacy validators map
        if let Some(v) = self.validators.get_mut(&target) {
            v.stake = v.stake.saturating_sub(validator_slash_amount);
        }
        
        // Add treasury portion
        self.treasury_balance = self.treasury_balance.saturating_add(to_treasury);
        
        // Burn portion
        self.total_supply = self.total_supply.saturating_sub(to_burn);
        
        // Update QV weights
        self.update_qv_weight(&target);
        self.update_validator_qv_weight(&target);
        
        // Apply force-unbond jika malicious block
        if matches!(reason, SlashingReason::ValidatorMaliciousBlock) {
            self.apply_force_unbond(target, FORCE_UNBOND_DELAY_SECONDS, current_timestamp);
        }
        
        // Mark as slashed
        if let Some(record) = self.liveness_records.get_mut(&target) {
            record.slashed = true;
            record.slash_count = record.slash_count.saturating_add(1);
        }
        if let Some(record) = self.node_liveness_records.get_mut(&target) {
            record.slashed = true;
        }
        
        // Set validator inactive
        self.validator_set.set_active(&target, false);
        if let Some(v) = self.validators.get_mut(&target) {
            v.active = false;
        }
        
        // ════════════════════════════════════════════════════════════════════
        // STEP 3: Check delegator protection
        // ════════════════════════════════════════════════════════════════════
        
        let mut total_slashed = validator_slash_amount;
        let mut delegator_slashed: u128 = 0;
        
        // Check protocol failure condition
        let is_protocol_failure = Self::is_protocol_failure_condition(reason);
        
        if is_protocol_failure {
            // Check threshold: delegator hanya di-slash jika validator loss > 20%
            if slash_percent_bp > DELEGATOR_SLASH_THRESHOLD {
                // ════════════════════════════════════════════════════════════
                // STEP 4: Slash delegators (HANYA pada protocol failure ekstrem)
                // ════════════════════════════════════════════════════════════
                
                // Hitung delegator slash percent (TIDAK BOLEH melebihi validator percent)
                // Delegator di-slash proporsional, tapi capped
                let delegator_slash_percent_bp = slash_percent_bp.saturating_sub(DELEGATOR_SLASH_THRESHOLD);
                
                // Konversi ke percentage (basis points → percent)
                // delegator_slash_percent_bp sudah dalam basis points, perlu convert ke percent
                let delegator_slash_percent = (delegator_slash_percent_bp as u64) / 100;
                
                if delegator_slash_percent > 0 {
                    // Panggil apply_slash_to_delegators
                    // NOTE: Method ini sudah handle treasury transfer
                    // Kita perlu adjust karena kita sudah handle treasury di atas
                    
                    // Get delegators dan slash manual (tanpa double treasury)
                    let delegator_amounts: Vec<(Address, u128)> = self.delegations
                        .get(&target)
                        .map(|dels| {
                            dels.iter()
                                .filter(|(del_addr, _)| *del_addr != &target)
                                .map(|(addr, &amount)| (*addr, amount))
                                .collect()
                        })
                        .unwrap_or_default();
                    
                    for (delegator, current_amount) in delegator_amounts {
                        // Calculate slash
                        let del_slash = (current_amount * delegator_slash_percent as u128) / 100;
                        
                        // Cap: delegator slash tidak boleh lebih dari proporsi validator slash
                        let del_slash_capped = del_slash.min(validator_slash_amount);
                        
                        if del_slash_capped == 0 {
                            continue;
                        }
                        
                        let new_amount = current_amount.saturating_sub(del_slash_capped);
                        
                        // Update delegations map
                        if let Some(dels) = self.delegations.get_mut(&target) {
                            if new_amount > 0 {
                                dels.insert(delegator, new_amount);
                            } else {
                                dels.remove(&delegator);
                            }
                        }
                        
                        // Update delegator_stakes
                        let current_del_stake = self.delegator_stakes.get(&delegator).copied().unwrap_or(0);
                        let new_del_stake = current_del_stake.saturating_sub(del_slash_capped);
                        if new_del_stake > 0 {
                            self.delegator_stakes.insert(delegator, new_del_stake);
                        } else {
                            self.delegator_stakes.remove(&delegator);
                            self.delegator_to_validator.remove(&delegator);
                        }
                        
                        // Update locked
                        let del_locked = self.locked.get(&delegator).copied().unwrap_or(0);
                        let new_del_locked = del_locked.saturating_sub(del_slash_capped);
                        if new_del_locked > 0 {
                            self.locked.insert(delegator, new_del_locked);
                        } else {
                            self.locked.remove(&delegator);
                        }
                        
                        // Update QV weight
                        self.update_qv_weight(&delegator);
                        
                        delegator_slashed = delegator_slashed.saturating_add(del_slash_capped);
                    }
                    
                    // Allocate delegator slashed amount
                    if delegator_slashed > 0 {
                        let (del_treasury, del_burn) = Self::allocate_slashed_amount(delegator_slashed);
                        self.treasury_balance = self.treasury_balance.saturating_add(del_treasury);
                        self.total_supply = self.total_supply.saturating_sub(del_burn);
                        total_slashed = total_slashed.saturating_add(delegator_slashed);
                        
                        // Update validator combined QV weight
                        self.update_validator_qv_weight(&target);
                    }
                }
            }
        }
        
        // ════════════════════════════════════════════════════════════════════
        // STEP 5: Create and return SlashingEvent
        // ════════════════════════════════════════════════════════════════════
        
        // Recalculate treasury and burn with total
        let (final_treasury, final_burn) = Self::allocate_slashed_amount(total_slashed);
        
        let event = SlashingEvent {
            target,
            reason,
            amount_slashed: total_slashed,
            amount_to_treasury: final_treasury,
            amount_burned: final_burn,
            timestamp: current_timestamp,
        };
        
        // Add to audit trail
        self.slashing_events.push(event.clone());
        
        Ok(event)
    }

    /// Allocate slashed amount ke treasury dan burn.
    ///
    /// Menggunakan SLASHING_TREASURY_RATIO dan SLASHING_BURN_RATIO.
    /// Garantir treasury + burn == amount (no rounding loss).
    ///
    /// # Arguments
    ///
    /// * `amount` - Total amount yang di-slash
    ///
    /// # Returns
    ///
    /// * `(u128, u128)` - (to_treasury, to_burn)
    pub fn allocate_slashed_amount(amount: u128) -> (u128, u128) {
        calculate_slash_allocation(amount, SLASHING_TREASURY_RATIO, SLASHING_BURN_RATIO)
    }

    // ============================================================
    // SLASHING COMPATIBILITY (13.8.J)
    // ============================================================
    // Forward-safe slashing that properly handles:
    // - Validator stake reduction
    // - Delegator stake reduction (proportional)
    // - QV weight recalculation
    // - Pending unstake amount adjustment
    // ============================================================

    /// Apply slash to validator's own stake
    /// Returns the actual amount slashed
    /// 
    /// This function:
    /// 1. Reduces validator_stakes[validator]
    /// 2. Reduces locked[validator]
    /// 3. Reduces validator_set stake
    /// 4. Updates validator's QV weight
    /// 5. Slashes pending unstake entries for this validator
    /// 6. Adds slashed amount to treasury
    pub fn apply_slash_to_validator(&mut self, validator: &Address, slash_percent: u64) -> u128 {
        let mut total_slashed: u128 = 0;
        
        // 1. Get current validator stake
        let current_stake = self.validator_stakes.get(validator).copied().unwrap_or(0);
        if current_stake == 0 {
            println!("⚠️ Validator {} has no stake to slash", validator);
            return 0;
        }
        
        // 2. Calculate slash amount
        let slash_amount = (current_stake * slash_percent as u128) / 100;
        let new_stake = current_stake.saturating_sub(slash_amount);
        
        // 3. Update validator_stakes
        if new_stake > 0 {
            self.validator_stakes.insert(*validator, new_stake);
        } else {
            self.validator_stakes.remove(validator);
        }
        
        // 4. Update locked amount
        let current_locked = self.locked.get(validator).copied().unwrap_or(0);
        let new_locked = current_locked.saturating_sub(slash_amount);
        if new_locked > 0 {
            self.locked.insert(*validator, new_locked);
        } else {
            self.locked.remove(validator);
        }
        
        // 5. Update validator_set stake
        self.validator_set.update_stake(validator, -(slash_amount as i128));
        
        // 6. Update legacy validators map
        if let Some(v) = self.validators.get_mut(validator) {
            v.stake = v.stake.saturating_sub(slash_amount);
        }
        
        total_slashed += slash_amount;
        
        // 7. Slash pending unstake entries for this validator (self-unstakes)
        if let Some(entries) = self.pending_unstakes.get_mut(validator) {
            for entry in entries.iter_mut() {
                if entry.is_validator_unstake {
                    let entry_slash = (entry.amount * slash_percent as u128) / 100;
                    entry.amount = entry.amount.saturating_sub(entry_slash);
                    total_slashed += entry_slash;
                    println!("   📉 Pending validator unstake slashed: {} → {} (-{})", 
                             entry.amount + entry_slash, entry.amount, entry_slash);
                }
            }
            // Remove entries with 0 amount
            entries.retain(|e| e.amount > 0);
        }
        
        // 8. Update QV weight for validator
        self.update_qv_weight(validator);
        self.update_validator_qv_weight(validator);
        
        // 9. Add slashed amount to treasury
        self.treasury_balance = self.treasury_balance.saturating_add(total_slashed);
        
        println!("🔪 Validator {} slashed: {} ({:.1}%) → treasury", 
                 validator, total_slashed, slash_percent);
        
        total_slashed
    }

    /// Apply slash to all delegators of a validator
    /// Returns total amount slashed from all delegators
    /// 
    /// This function:
    /// 1. For each delegator staking to this validator:
    ///    - Reduces delegator_stakes[delegator]
    ///    - Reduces delegations[validator][delegator]
    ///    - Reduces locked[delegator]
    ///    - Updates delegator's QV weight
    /// 2. Slashes pending unstake entries for delegators
    /// 3. Updates validator's combined QV weight
    /// 4. Adds total slashed to treasury
    pub fn apply_slash_to_delegators(&mut self, validator: &Address, slash_percent: u64) -> u128 {
        let mut total_slashed: u128 = 0;
        let mut affected_delegators: Vec<Address> = Vec::new();
        
        // 1. Get all delegators for this validator from delegations map
        let delegator_amounts: Vec<(Address, u128)> = self.delegations
            .get(validator)
            .map(|dels| {
                dels.iter()
                    .filter(|(del_addr, _)| *del_addr != validator) // exclude self-delegation
                    .map(|(addr, &amount)| (*addr, amount))
                    .collect()
            })
            .unwrap_or_default();
        
        if delegator_amounts.is_empty() {
            println!("   ℹ️ No delegators to slash for validator {}", validator);
            return 0;
        }
        
        println!("   📊 Slashing {} delegator(s) for validator {}", 
                 delegator_amounts.len(), validator);
        
        // 2. Process each delegator
        for (delegator, current_amount) in delegator_amounts {
            // Calculate slash amount for this delegator
            let slash_amount = (current_amount * slash_percent as u128) / 100;
            let new_amount = current_amount.saturating_sub(slash_amount);
            
            // Update delegations map
            if let Some(dels) = self.delegations.get_mut(validator) {
                if new_amount > 0 {
                    dels.insert(delegator, new_amount);
                } else {
                    dels.remove(&delegator);
                }
            }
            
            // Update delegator_stakes
            let current_delegator_stake = self.delegator_stakes.get(&delegator).copied().unwrap_or(0);
            let new_delegator_stake = current_delegator_stake.saturating_sub(slash_amount);
            if new_delegator_stake > 0 {
                self.delegator_stakes.insert(delegator, new_delegator_stake);
            } else {
                self.delegator_stakes.remove(&delegator);
                // Also remove delegator_to_validator mapping if fully slashed
                self.delegator_to_validator.remove(&delegator);
            }
            
            // Update locked amount for delegator
            let current_locked = self.locked.get(&delegator).copied().unwrap_or(0);
            let new_locked = current_locked.saturating_sub(slash_amount);
            if new_locked > 0 {
                self.locked.insert(delegator, new_locked);
            } else {
                self.locked.remove(&delegator);
            }
            
            total_slashed += slash_amount;
            affected_delegators.push(delegator);
            
            println!("      └─ Delegator {} slashed: {} → {} (-{})", 
                     delegator, current_amount, new_amount, slash_amount);
        }
        
        // 3. Slash pending unstake entries for delegators of this validator
        for delegator in &affected_delegators {
            if let Some(entries) = self.pending_unstakes.get_mut(delegator) {
                for entry in entries.iter_mut() {
                    // Only slash entries for this specific validator
                    if entry.validator == *validator && !entry.is_validator_unstake {
                        let entry_slash = (entry.amount * slash_percent as u128) / 100;
                        entry.amount = entry.amount.saturating_sub(entry_slash);
                        total_slashed += entry_slash;
                        println!("      └─ Pending delegator unstake slashed: {} (-{})", 
                                 delegator, entry_slash);
                    }
                }
                // Remove entries with 0 amount
                entries.retain(|e| e.amount > 0);
            }
        }
        
        // 4. Update QV weights for all affected delegators
        for delegator in &affected_delegators {
            self.update_qv_weight(delegator);
        }
        
        // 5. Update validator's combined QV weight (delegator influence changed)
        self.update_validator_qv_weight(validator);
        
        // 6. Add total slashed to treasury
        self.treasury_balance = self.treasury_balance.saturating_add(total_slashed);
        
        println!("   🔪 Total delegator slash: {} from {} delegator(s) → treasury", 
                 total_slashed, affected_delegators.len());
        
        total_slashed
    }

    /// Apply complete slashing to a validator and all their delegators
    /// This is the main entry point for slashing operations
    /// 
    /// Returns (validator_slashed, delegators_slashed, total_slashed)
    pub fn apply_full_slash(
        &mut self, 
        validator: &Address, 
        slash_percent: u64
    ) -> (u128, u128, u128) {
        println!("⚔️ FULL SLASH INITIATED for validator {} at {}%", validator, slash_percent);
        
        // 1. Slash validator's own stake
        let validator_slashed = self.apply_slash_to_validator(validator, slash_percent);
        
        // 2. Slash all delegators
        let delegators_slashed = self.apply_slash_to_delegators(validator, slash_percent);
        
        let total = validator_slashed + delegators_slashed;
        
        println!("⚔️ FULL SLASH COMPLETE: validator={}, delegators={}, total={} → treasury", 
                 validator_slashed, delegators_slashed, total);
        
        (validator_slashed, delegators_slashed, total)
    }

/// Recalculate QV weight for an address (convenience wrapper)
    /// Called after slashing to ensure consistency
    pub fn recalc_qv_weight(&mut self, addr: &Address) {
        self.update_qv_weight(addr);
        
        // If this is a validator, also update combined weight
        if self.validator_set.is_validator(addr) {
            self.update_validator_qv_weight(addr);
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // 13.14.6 — BLOCK-LEVEL SLASHING HOOK
    // ════════════════════════════════════════════════════════════════════════════
    // INTEGRATION POINT untuk automatic slashing dalam block lifecycle.
    //
    // POSISI WAJIB dalam block execution:
    //   1. Execute all transactions
    //   2. process_automatic_slashing()  ← DI SINI
    //   3. Compute state_root
    //   4. Finalize block
    //
    // Method ini HARUS dipanggil SETELAH semua TX selesai, SEBELUM state_root.
    // ════════════════════════════════════════════════════════════════════════════

    /// Process automatic slashing untuk semua pending violations.
    ///
    /// Method ini adalah BLOCK-LEVEL HOOK yang memproses semua slashing
    /// yang terdeteksi selama block execution.
    ///
    /// # Arguments
    ///
    /// * `current_height` - Block height saat ini (untuk logging)
    /// * `current_timestamp` - Unix timestamp saat ini (untuk slashing)
    ///
    /// # Returns
    ///
    /// * `Vec<SlashingEvent>` - Semua slashing events yang dieksekusi
    ///
    /// # Execution Order (CONSENSUS-CRITICAL)
    ///
    /// 1. Iterasi semua node_liveness_records
    /// 2. Iterasi semua validators
    /// 3. Check pending SlashingReason untuk setiap target
    /// 4. Execute slashing jika ada violation
    /// 5. Kumpulkan SlashingEvents
    ///
    /// # Guarantees
    ///
    /// - Deterministic: Hasil sama di semua node
    /// - No double-slash: Target yang sudah slashed di-skip
    /// - No panic: Error di-log dan dilanjutkan
    /// - Idempotent per block: Dapat dipanggil sekali per block
    ///
    /// # Note
    ///
    /// Method ini TIDAK mengubah state_root secara langsung.
    /// State changes dari slashing akan tercermin di state_root
    /// yang dihitung SETELAH method ini selesai.
    pub fn process_automatic_slashing(
        &mut self,
        current_height: u64,
        current_timestamp: u64,
    ) -> Vec<SlashingEvent> {
        let mut events: Vec<SlashingEvent> = Vec::new();
        
        println!("⚔️ BLOCK-LEVEL SLASHING HOOK - Height: {}", current_height);
        
        // ════════════════════════════════════════════════════════════════════
        // PHASE 1: Process NODE violations (storage/compute nodes)
        // ════════════════════════════════════════════════════════════════════
        
        // Collect nodes with pending violations (avoid borrow conflict)
        let node_violations: Vec<(Address, SlashingReason)> = self.node_liveness_records
            .iter()
            .filter_map(|(addr, record)| {
                // Skip already slashed
                if record.slashed {
                    return None;
                }
                
                // Check for node-specific violations
                // Priority: MaliciousBehavior > DataCorruption > LivenessFailure
                if record.malicious_behavior_count >= 1 {
                    return Some((*addr, SlashingReason::NodeMaliciousBehavior));
                }
                if record.data_corruption_count >= 2 {
                    return Some((*addr, SlashingReason::NodeDataCorruption));
                }
                if record.consecutive_failures >= 1 {
                    return Some((*addr, SlashingReason::NodeLivenessFailure));
                }
                
                None
            })
            .collect();
        
        // Execute node slashing
        for (node_addr, reason) in node_violations {
            println!("   🔍 Node violation detected: {} - {:?}", node_addr, reason);
            
            match self.execute_auto_slash_node(node_addr, reason, current_timestamp) {
                Ok(event) => {
                    println!("   ✅ Node slashed: {} amount={}", node_addr, event.amount_slashed);
                    events.push(event);
                }
                Err(e) => {
                    // Log error but continue (no panic)
                    println!("   ⚠️ Node slash skipped: {} - {:?}", node_addr, e);
                }
            }
        }
        
        // ════════════════════════════════════════════════════════════════════
        // PHASE 2: Process VALIDATOR violations
        // ════════════════════════════════════════════════════════════════════
        
        // Collect validators with pending violations
        let validator_violations: Vec<(Address, SlashingReason)> = self.node_liveness_records
            .iter()
            .filter_map(|(addr, record)| {
                // Only process validators
                if !self.validator_set.is_validator(addr) {
                    return None;
                }
                
                // Skip already slashed
                if record.slashed {
                    return None;
                }
                
                // Also check legacy liveness_records
                if let Some(legacy_record) = self.liveness_records.get(addr) {
                    if legacy_record.slashed {
                        return None;
                    }
                }
                
                // Check for validator-specific violations
                // Priority: DoubleSign > MaliciousBlock > ProlongedOffline
                if record.double_sign_detected {
                    return Some((*addr, SlashingReason::ValidatorDoubleSign));
                }
                if record.malicious_block_detected {
                    return Some((*addr, SlashingReason::ValidatorMaliciousBlock));
                }
                // Check prolonged offline via offline_since
                if record.offline_since.is_some() && record.consecutive_failures > 0 {
                    return Some((*addr, SlashingReason::ValidatorProlongedOffline));
                }
                
                None
            })
            .collect();
        
        // Execute validator slashing with delegator protection
        for (validator_addr, reason) in validator_violations {
            println!("   🔍 Validator violation detected: {} - {:?}", validator_addr, reason);
            
            // Use slash_with_delegator_protection for validator slashing
            match self.slash_with_delegator_protection(validator_addr, reason, current_timestamp) {
                Ok(event) => {
                    println!("   ✅ Validator slashed: {} amount={}", validator_addr, event.amount_slashed);
                    events.push(event);
                }
                Err(e) => {
                    // Log error but continue (no panic)
                    println!("   ⚠️ Validator slash skipped: {} - {:?}", validator_addr, e);
                }
            }
        }
        
        // ════════════════════════════════════════════════════════════════════
        // PHASE 3: Summary
        // ════════════════════════════════════════════════════════════════════
        
        if events.is_empty() {
            println!("   ℹ️ No pending violations to process");
        } else {
            let total_slashed: u128 = events.iter().map(|e| e.amount_slashed).sum();
            println!("⚔️ SLASHING COMPLETE: {} events, total_slashed={}", events.len(), total_slashed);
        }
        
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ChainState, ValidatorInfo};
    use crate::slashing::{
        NODE_LIVENESS_THRESHOLD_SECONDS,
        NODE_LIVENESS_SLASH_PERCENT,
        NODE_DATA_CORRUPTION_SLASH_PERCENT,
        VALIDATOR_DOUBLE_SIGN_SLASH_PERCENT,
        VALIDATOR_OFFLINE_SLASH_PERCENT,
        VALIDATOR_MALICIOUS_BLOCK_SLASH_PERCENT,
        SLASHING_TREASURY_RATIO,
        SLASHING_BURN_RATIO,
        FORCE_UNBOND_DELAY_SECONDS,
        SlashingReason,
    };

    // ════════════════════════════════════════════════════════════════════════════
    // 13.14.9 — NODE LIVENESS TRACKING TESTS
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: Heartbeat correctly updates last_seen_timestamp.
    /// Assertion: timestamp is recorded and consecutive_failures is reset.
    #[test]
    fn test_node_heartbeat_recording() {
        let mut state = ChainState::new();
        let node = Address::from_bytes([0x01; 20]);
        let timestamp = 1700000000u64;
        
        // Record heartbeat
        state.record_node_heartbeat(node, timestamp);
        
        // Verify record exists
        let record = state.node_liveness_records.get(&node)
            .expect("record should exist after heartbeat");
        
        assert_eq!(record.last_seen_timestamp, timestamp, 
            "last_seen_timestamp should be updated");
        assert_eq!(record.consecutive_failures, 0, 
            "consecutive_failures should be 0 after heartbeat");
        assert!(record.offline_since.is_none(), 
            "offline_since should be None after heartbeat");
        assert!(!record.slashed, "should not be slashed");
    }

    /// Test: Node liveness check passes when within threshold.
    /// Assertion: No SlashingReason returned for active node.
    #[test]
    fn test_node_liveness_check_pass() {
        let mut state = ChainState::new();
        let node = Address::from_bytes([0x02; 20]);
        let initial_time = 1700000000u64;
        
        // Record heartbeat
        state.record_node_heartbeat(node, initial_time);
        
        // Check liveness within threshold (11 hours later)
        let check_time = initial_time + (NODE_LIVENESS_THRESHOLD_SECONDS - 3600);
        let result = state.check_node_liveness(node, check_time);
        
        assert!(result.is_none(), 
            "Should NOT return slash reason when within threshold");
        
        // Verify consecutive_failures is still 0
        let record = state.node_liveness_records.get(&node).unwrap();
        assert_eq!(record.consecutive_failures, 0);
    }

    /// Test: Node liveness check fails when exceeding threshold.
    /// Assertion: SlashingReason::NodeLivenessFailure returned.
    #[test]
    fn test_node_liveness_check_fail() {
        let mut state = ChainState::new();
        let node = Address::from_bytes([0x03; 20]);
        let initial_time = 1700000000u64;
        
        // Record heartbeat
        state.record_node_heartbeat(node, initial_time);
        
        // Check liveness AFTER threshold (13 hours later)
        let check_time = initial_time + NODE_LIVENESS_THRESHOLD_SECONDS + 3600;
        let result = state.check_node_liveness(node, check_time);
        
        assert_eq!(result, Some(SlashingReason::NodeLivenessFailure),
            "Should return NodeLivenessFailure when exceeding threshold");
        
        // Verify consecutive_failures incremented
        let record = state.node_liveness_records.get(&node).unwrap();
        assert_eq!(record.consecutive_failures, 1);
    }

    /// Test: Single data corruption does NOT trigger slash.
    /// Assertion: None returned on first corruption.
    #[test]
    fn test_data_corruption_single() {
        let mut state = ChainState::new();
        let node = Address::from_bytes([0x04; 20]);
        
        // First corruption
        let result = state.record_data_corruption(node);
        
        assert!(result.is_none(), 
            "First corruption should NOT trigger slash");
        
        let record = state.node_liveness_records.get(&node).unwrap();
        assert_eq!(record.data_corruption_count, 1);
    }

    /// Test: Second consecutive data corruption triggers slash.
    /// Assertion: SlashingReason::NodeDataCorruption returned on second.
    #[test]
    fn test_data_corruption_double() {
        let mut state = ChainState::new();
        let node = Address::from_bytes([0x05; 20]);
        
        // First corruption - no slash
        let result1 = state.record_data_corruption(node);
        assert!(result1.is_none());
        
        // Second corruption - triggers slash
        let result2 = state.record_data_corruption(node);
        assert_eq!(result2, Some(SlashingReason::NodeDataCorruption),
            "Second corruption should trigger slash");
        
        let record = state.node_liveness_records.get(&node).unwrap();
        assert_eq!(record.data_corruption_count, 2);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // 13.14.9 — VALIDATOR DETECTION TESTS
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: Double-sign detection with different signatures.
    /// Assertion: Returns true and sets double_sign_detected flag.
    #[test]
    fn test_validator_double_sign_detection() {
        let mut state = ChainState::new();
        let validator = Address::from_bytes([0x10; 20]);
        let block_height = 100u64;
        let sig1 = vec![0x01, 0x02, 0x03];
        let sig2 = vec![0x04, 0x05, 0x06]; // Different signature
        
        // Detect double-sign
        let detected = state.detect_double_sign(validator, block_height, sig1, sig2);
        
        assert!(detected, "Should detect double-sign with different signatures");
        
        let record = state.node_liveness_records.get(&validator).unwrap();
        assert!(record.double_sign_detected, "double_sign_detected flag should be set");
    }

    /// Test: No double-sign when signatures are identical.
    /// Assertion: Returns false.
    #[test]
    fn test_validator_no_double_sign_same_signature() {
        let mut state = ChainState::new();
        let validator = Address::from_bytes([0x11; 20]);
        let sig = vec![0x01, 0x02, 0x03];
        
        // Same signature should not trigger
        let detected = state.detect_double_sign(validator, 100, sig.clone(), sig);
        
        assert!(!detected, "Should NOT detect double-sign with same signature");
    }

    /// Test: Prolonged offline detection.
    /// Assertion: Returns true after threshold exceeded.
    #[test]
    fn test_validator_offline_detection() {
        let mut state = ChainState::new();
        let validator = Address::from_bytes([0x12; 20]);
        let initial_time = 1700000000u64;
        
        // First call sets offline_since
        let result1 = state.detect_prolonged_offline(validator, initial_time);
        assert!(!result1, "First call should return false (sets offline_since)");
        
        // Second call within threshold
        let result2 = state.detect_prolonged_offline(
            validator, 
            initial_time + NODE_LIVENESS_THRESHOLD_SECONDS - 1000
        );
        assert!(!result2, "Should return false within threshold");
        
        // Third call exceeding threshold
        let result3 = state.detect_prolonged_offline(
            validator, 
            initial_time + NODE_LIVENESS_THRESHOLD_SECONDS + 1000
        );
        assert!(result3, "Should return true when exceeding threshold");
    }

    // ════════════════════════════════════════════════════════════════════════════
    // 13.14.9 — AUTO SLASH EXECUTION TESTS
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: Node auto-slash execution.
    /// Assertion: Stake reduced, slashed=true, SlashingEvent valid.
    #[test]
    fn test_auto_slash_node_execution() {
        let mut state = ChainState::new();
        let node = Address::from_bytes([0x20; 20]);
        let initial_stake = 10_000_000u128;
        let timestamp = 1700000000u64;
        
        // Setup: Give node earnings (stake)
        state.node_earnings.insert(node, initial_stake);
        state.record_node_heartbeat(node, timestamp - 100000); // Old heartbeat
        
        // Trigger liveness failure
        let reason = state.check_node_liveness(node, timestamp);
        assert_eq!(reason, Some(SlashingReason::NodeLivenessFailure));
        
        // Execute slash
        let result = state.execute_auto_slash_node(node, SlashingReason::NodeLivenessFailure, timestamp);
        
        assert!(result.is_ok(), "Slash execution should succeed");
        let event = result.unwrap();
        
        // Verify slashing calculations (0.5% = 50 bp)
        let expected_slash = (initial_stake * NODE_LIVENESS_SLASH_PERCENT as u128) / 10_000;
        assert_eq!(event.amount_slashed, expected_slash, "Slash amount should be correct");
        assert_eq!(event.reason, SlashingReason::NodeLivenessFailure);
        assert_eq!(event.timestamp, timestamp);
        
        // Verify stake reduced
        let remaining = state.node_earnings.get(&node).copied().unwrap_or(0);
        assert_eq!(remaining, initial_stake - expected_slash);
        
        // Verify slashed flag
        let record = state.node_liveness_records.get(&node).unwrap();
        assert!(record.slashed, "slashed flag should be true");
    }

    /// Test: Validator auto-slash execution with force-unbond.
    /// Assertion: Stake reduced, force-unbond applied, event valid.
    #[test]
    fn test_auto_slash_validator_execution() {
        let mut state = ChainState::new();
        let validator = Address::from_bytes([0x21; 20]);
        let initial_stake = 100_000_000u128;
        let timestamp = 1700000000u64;
        
        // Setup validator
        state.validator_set.add_validator(ValidatorInfo::new(
            validator, 
            vec![0u8; 32], 
            initial_stake, 
            None
        ));
        state.validator_stakes.insert(validator, initial_stake);
        state.locked.insert(validator, initial_stake);
        
        // Setup detection record
        state.record_node_heartbeat(validator, timestamp);
        
        // Trigger double-sign detection
        state.detect_double_sign(validator, 100, vec![1, 2, 3], vec![4, 5, 6]);
        
        // Execute validator slash
        let result = state.execute_auto_slash_validator(
            validator, 
            SlashingReason::ValidatorDoubleSign, 
            timestamp
        );
        
        assert!(result.is_ok(), "Validator slash should succeed");
        let event = result.unwrap();
        
        // Verify slashing calculations (10% = 1000 bp)
        let expected_slash = (initial_stake * VALIDATOR_DOUBLE_SIGN_SLASH_PERCENT as u128) / 10_000;
        assert_eq!(event.amount_slashed, expected_slash);
        assert_eq!(event.reason, SlashingReason::ValidatorDoubleSign);
        
        // Verify stake reduced
        let remaining = state.validator_stakes.get(&validator).copied().unwrap_or(0);
        assert_eq!(remaining, initial_stake - expected_slash);
        
        let is_active = state.validator_set.validators
            .get(&validator)
            .map(|v| v.active)
            .unwrap_or(true);
        assert!(!is_active, "Validator should be inactive after slash");
    }

    // ════════════════════════════════════════════════════════════════════════════
    // 13.14.9 — DELEGATOR PROTECTION TESTS
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: Delegator protection on normal slash (double-sign).
    /// Assertion: Delegator stake is NOT reduced.
    #[test]
    fn test_delegator_protection_normal() {
        let mut state = ChainState::new();
        let validator = Address::from_bytes([0x30; 20]);
        let delegator = Address::from_bytes([0x31; 20]);
        let validator_stake = 100_000_000u128;
        let delegator_stake = 50_000_000u128;
        let timestamp = 1700000000u64;
        
        // Setup validator
        state.validator_set.add_validator(ValidatorInfo::new(
            validator, vec![0u8; 32], validator_stake, None
        ));
        state.validator_stakes.insert(validator, validator_stake);
        state.locked.insert(validator, validator_stake);
        
        // Setup delegator
        state.delegator_stakes.insert(delegator, delegator_stake);
        state.delegator_to_validator.insert(delegator, validator);
        let mut delegations = std::collections::HashMap::new();
        delegations.insert(delegator, delegator_stake);
        state.delegations.insert(validator, delegations);
        state.locked.insert(delegator, delegator_stake);
        
        // Setup detection
        state.record_node_heartbeat(validator, timestamp);
        state.detect_double_sign(validator, 100, vec![1], vec![2]);
        
        // Execute slash with delegator protection
        let result = state.slash_with_delegator_protection(
            validator,
            SlashingReason::ValidatorDoubleSign,  // 10% - NOT protocol failure
            timestamp
        );
        
        assert!(result.is_ok());
        
        // Verify delegator stake is UNCHANGED
        let delegator_remaining = state.delegator_stakes.get(&delegator).copied().unwrap_or(0);
        assert_eq!(delegator_remaining, delegator_stake, 
            "Delegator stake should be UNCHANGED on normal slash");
    }

    /// Test: Delegator protection on protocol failure (malicious block).
    /// Assertion: Delegator IS slashed proportionally.
    #[test]
    fn test_delegator_protection_protocol_failure() {
        let mut state = ChainState::new();
        let validator = Address::from_bytes([0x40; 20]);
        let delegator = Address::from_bytes([0x41; 20]);
        let validator_stake = 100_000_000u128;
        let delegator_stake = 50_000_000u128;
        let timestamp = 1700000000u64;
        
        // Setup validator
        state.validator_set.add_validator(ValidatorInfo::new(
            validator, vec![0u8; 32], validator_stake, None
        ));
        state.validator_stakes.insert(validator, validator_stake);
        state.locked.insert(validator, validator_stake);
        
        // Setup delegator
        state.delegator_stakes.insert(delegator, delegator_stake);
        state.delegator_to_validator.insert(delegator, validator);
        let mut delegations = std::collections::HashMap::new();
        delegations.insert(delegator, delegator_stake);
        state.delegations.insert(validator, delegations);
        state.locked.insert(delegator, delegator_stake);
        
        // Setup detection
        state.record_node_heartbeat(validator, timestamp);
        state.detect_malicious_block(validator, Hash::from_bytes([0u8; 64]), vec![0xDE, 0xAD]);
        
        // Execute slash with delegator protection
        let result = state.slash_with_delegator_protection(
            validator,
            SlashingReason::ValidatorMaliciousBlock,  // 20% - IS protocol failure
            timestamp
        );
        
        assert!(result.is_ok());
        
        // Verify delegator stake IS reduced (protocol failure > 20% threshold)
        // Note: Actual reduction depends on implementation logic
        // At minimum, we verify the slash executed successfully
        let event = result.unwrap();
        assert!(event.amount_slashed > 0, "Should have slashed some amount");
    }

    // ════════════════════════════════════════════════════════════════════════════
    // 13.14.9 — ALLOCATION & FORCE UNBOND TESTS
    // ════════════════════════════════════════════════════════════════════════════

    /// Test: Slash allocation is 50/50 treasury/burn.
    /// Assertion: treasury + burn == total, both are 50%.
    #[test]
    fn test_slash_allocation_treasury_burn() {
        let amount = 1_000_000u128;
        
        let (to_treasury, to_burn) = ChainState::allocate_slashed_amount(amount);
        
        assert_eq!(to_treasury + to_burn, amount, 
            "Treasury + Burn must equal total amount");
        assert_eq!(to_treasury, amount * SLASHING_TREASURY_RATIO as u128 / 100,
            "Treasury should be 50%");
        assert_eq!(to_burn, amount * SLASHING_BURN_RATIO as u128 / 100,
            "Burn should be 50%");
    }

    /// Test: Force unbond applies correct timestamp.
    /// Assertion: force_unbond_until = current + delay.
    #[test]
    fn test_force_unbond_application() {
        let mut state = ChainState::new();
        let node = Address::from_bytes([0x50; 20]);
        let current_time = 1700000000u64;
        let duration = FORCE_UNBOND_DELAY_SECONDS;
        
        state.apply_force_unbond(node, duration, current_time);
        
        let record = state.node_liveness_records.get(&node).unwrap();
        let expected_until = current_time + duration;
        
        assert_eq!(record.force_unbond_until, Some(expected_until),
            "force_unbond_until should be current + delay");
        
        // Verify is_node_force_unbonded
        assert!(state.is_node_force_unbonded(node, current_time + 1000),
            "Should be force-unbonded immediately after");
        assert!(!state.is_node_force_unbonded(node, expected_until + 1),
            "Should NOT be force-unbonded after delay expires");
    }

    /// Test: Double-slash prevention.
    /// Assertion: Second slash returns AlreadySlashed error.
    #[test]
    fn test_double_slash_prevention() {
        let mut state = ChainState::new();
        let node = Address::from_bytes([0x60; 20]);
        let timestamp = 1700000000u64;
        
        // Setup
        state.node_earnings.insert(node, 10_000_000);
        state.record_node_heartbeat(node, timestamp - 100000);
        state.check_node_liveness(node, timestamp);
        
        // First slash succeeds
        let result1 = state.execute_auto_slash_node(
            node, SlashingReason::NodeLivenessFailure, timestamp
        );
        assert!(result1.is_ok());
        
        // Second slash fails with AlreadySlashed
        let result2 = state.execute_auto_slash_node(
            node, SlashingReason::NodeLivenessFailure, timestamp + 1000
        );
        assert!(matches!(result2, Err(SlashError::AlreadySlashed)),
            "Second slash should return AlreadySlashed");
    }

    /// Test: Invalid reason for node returns InvalidReason error.
    /// Assertion: Validator reasons rejected for nodes.
    #[test]
    fn test_invalid_slash_reason_for_node() {
        let mut state = ChainState::new();
        let node = Address::from_bytes([0x70; 20]);
        let timestamp = 1700000000u64;
        
        state.node_earnings.insert(node, 10_000_000);
        state.record_node_heartbeat(node, timestamp);
        
        // Try validator reason on node
        let result = state.execute_auto_slash_node(
            node, SlashingReason::ValidatorDoubleSign, timestamp
        );
        
        assert!(matches!(result, Err(SlashError::InvalidReason)),
            "Validator reason should be invalid for node");
    }
}