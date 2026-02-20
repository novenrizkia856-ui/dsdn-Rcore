//! Internal payload execution logic
//! Dipindahkan dari state.rs untuk modularisasi
//! SIGNATURE TIDAK BOLEH BERUBAH

use crate::types::Address;
use crate::tx::{TxEnvelope, TxPayload, GovernanceActionType};
use anyhow::Result;
use std::collections::HashMap;
use super::{ChainState, Validator, ValidatorInfo};
use super::internal_gas;
use super::internal_governance::{
    GovernanceEvent, GovernanceEventType,
    ProposalStatus,
};
use crate::gating::ServiceNodeRecord;
use dsdn_common::gating::{NodeClass, NodeStatus};

// Gas constants
#[allow(dead_code)]
const FIXED_GAS_TRANSFER: u64 = 21000;
#[allow(dead_code)]
const FIXED_GAS_STAKE: u64 = 30000;
const FIXED_GAS_CLAIM: u64 = 15000;
#[allow(dead_code)]
const FIXED_GAS_STORAGE: u64 = 25000;
#[allow(dead_code)]
const FIXED_GAS_COMPUTE: u64 = 40000;
#[allow(dead_code)]
const FIXED_GAS_REGISTRATION: u64 = 50000;
#[allow(dead_code)]
const FIXED_GAS_GOV: u64 = 10000;
#[allow(dead_code)]
const FIXED_GAS_CUSTOM: u64 = 21000;
const PRIVATE_TX_BASE_GAS: u64 = 21000;    // Base gas untuk private tx relay (13.7.F)
#[allow(dead_code)]
const MIN_DELEGATOR_STAKE: u128 = 100_000;

// Service node min stake per NodeClass (14B.13)
const MIN_SERVICE_NODE_STAKE_COMPUTE: u128 = 500;
const MIN_SERVICE_NODE_STAKE_STORAGE: u128 = 5_000;

/// Determine minimum stake requirement based on NodeClass
fn min_stake_for_node_class(class: &NodeClass) -> u128 {
    match class {
        NodeClass::Storage => MIN_SERVICE_NODE_STAKE_STORAGE,
        NodeClass::Compute => MIN_SERVICE_NODE_STAKE_COMPUTE,
    }
}

impl ChainState {
    // ============================================================
    // Anti Self-Dealing Check (13.7.E)
    // ============================================================

    /// Check if transaction is self-dealing (validator processing tx to themselves)
    /// Self-dealing is NOT allowed for Storage and Compute payments
    /// Returns true if self-dealing detected (tx should be rejected)
    pub fn is_self_dealing(&self, validator: &Address, payload: &TxPayload) -> bool {
        let sender = match payload {
            TxPayload::Transfer { from, .. } => from,
            TxPayload::Stake { delegator, .. } => delegator,
            TxPayload::Unstake { delegator, .. } => delegator,
             TxPayload::ClaimReward { receipt, .. } => &receipt.node_address,
            TxPayload::StorageOperationPayment { from, .. } => from,
            TxPayload::ComputeExecutionPayment { from, .. } => from,
            TxPayload::ValidatorRegistration { from, .. } => from,
            TxPayload::RegisterServiceNode { from, .. } => from,
            TxPayload::GovernanceAction { from, .. } => from,
            TxPayload::Custom { .. } => return false,
        };

        sender == validator
    }

    /// Get the target node address from payload (for self-dealing check)
    pub fn get_target_node(&self, payload: &TxPayload) -> Option<Address> {
        match payload {
            TxPayload::StorageOperationPayment { to_node, .. } => Some(*to_node),
            TxPayload::ComputeExecutionPayment { to_node, .. } => Some(*to_node),
            _ => None,
        }
    }

    pub fn apply_payload(&mut self, env: &TxEnvelope, miner_addr: &Address) -> Result<(u64, Vec<String>)> {
        use anyhow::anyhow;

        // === VALIDATOR COMPLIANCE FILTER ===
        if env.payload.is_flagged_illegal() {
            anyhow::bail!("illegal transaction blocked by validator compliance");
        }

        // === PRIVATE TX SKIP EXECUTION 
        // Private tx tidak dieksekusi di sini (akan dieksekusi oleh compute/storage node khusus)
        if env.is_private() {
            println!("🔒 PRIVATE TX DETECTED - Blind execution mode");
            println!("   ⚠️  Validator CANNOT read payload details");
            
            // Ambil sender dari signature (bukan dari payload)
            let sender = env.sender_address()?.ok_or(anyhow!("private tx requires sender"))?;
            
            // Gunakan helper get_blind_info untuk ambil minimal info
            // Validator HANYA boleh mengakses fee, gas_limit, nonce
            let (fee, gas_limit, _nonce) = env.payload.get_blind_info();
            let resource_class = env.payload.resource_class();

            // Gunakan base gas untuk private tx (tidak baca detail)
            let gas_used = PRIVATE_TX_BASE_GAS.max(gas_limit);
            let gas_cost = gas_used as u128; // GAS_PRICE = 1
            let total_deduct = fee + gas_cost;

            // Deduct fee + gas dari sender
            let sender_bal = self.balances.entry(sender).or_insert(0);
            if *sender_bal < total_deduct {
                anyhow::bail!("insufficient balance for private tx relay");
            }
            *sender_bal -= total_deduct;

            // Credit ke miner/proposer (100% untuk relay fee)
            *self.balances.entry(*miner_addr).or_insert(0) += total_deduct;

            // Increment nonce (untuk replay protection)
            self.increment_nonce(&sender);

            println!("   ✅ Private TX relayed successfully");
            println!("   💰 Fee charged: {} (fee: {} + gas: {})", total_deduct, fee, gas_cost);
            println!("   📍 ResourceClass: {:?} (tidak dieksekusi)", resource_class);

            return Ok((gas_used, vec![
                "private_tx_relayed".to_string(),
                format!("resource_class={:?}", resource_class),
                "blind_execution=true".to_string(),
            ]));
        }

        // Ambil sender dulu di awal (fix lifetime error)
        let sender = if let TxPayload::Custom { .. } = &env.payload {
            env.sender_address()?.ok_or(anyhow!("custom tx requires sender"))?
        } else {
            // semua payload lain punya field sender langsung
            match &env.payload {
                TxPayload::Transfer { from, .. } => *from,
                TxPayload::Stake { delegator, .. } => *delegator,
                TxPayload::Unstake { delegator, .. } => *delegator,
                TxPayload::ClaimReward { receipt, .. } => receipt.node_address,
                TxPayload::StorageOperationPayment { from, .. } => *from,
                TxPayload::ComputeExecutionPayment { from, .. } => *from,
                TxPayload::ValidatorRegistration { from, .. } => *from,
                TxPayload::RegisterServiceNode { from, .. } => *from,
                TxPayload::GovernanceAction { from, .. } => *from,
                _ => unreachable!(),
            }
        };

        // === DEBUG: TRACE BALANCES & TX METADATA (for failing test) ===
        println!("🔎 apply_payload debug: tx resource_class={:?}", env.payload.resource_class());
        println!("🔎 Sender: {} ; miner_addr: {}", sender, miner_addr);
        let sender_bal_before = self.balances.get(&sender).cloned().unwrap_or(0u128);
        let target_opt = match &env.payload {
            TxPayload::Transfer { to, .. } => Some(*to),
            TxPayload::StorageOperationPayment { to_node, .. } => Some(*to_node),
            TxPayload::ComputeExecutionPayment { to_node, .. } => Some(*to_node),
            _ => None,
        };
        if let Some(target) = target_opt {
            let target_bal_before = self.balances.get(&target).cloned().unwrap_or(0u128);
            println!("   Balance before: sender={} target={} ", sender_bal_before, target_bal_before);
        } else {
            println!("   Balance before: sender={} target=None", sender_bal_before);
        }

        // Di dalam apply_payload, tambahkan setelah ambil sender
        let resource_class = env.payload.resource_class();
        println!("Executing tx with resource_class: {:?}", resource_class);

        // Eksekusi efek khusus per jenis tx
        let (amount_to_transfer, to_opt): (u128, Option<Address>) = match &env.payload {
            TxPayload::Transfer { to, amount, .. } => (*amount, Some(*to)),
            TxPayload::StorageOperationPayment { to_node, amount, .. } => (*amount, Some(*to_node)),
            TxPayload::ComputeExecutionPayment { to_node, amount, .. } => (*amount, Some(*to_node)),

            TxPayload::Stake { delegator, validator, amount, bond, .. } => {
                if *bond {
                    // === DELEGATION RULES (13.8.B) ===
                    // Determine if this is self-delegation (validator) or external delegation
                    
                    if delegator == validator {
                        // SELF-STAKE VALIDATOR (JALUR KHUSUS)

                        // 1. balance → validator_stakes + locked
                        self.deposit_validator_stake(delegator, *amount)?;

                        // 2. pastikan delegations KEISI utk query
                        let dels = self
                            .delegations
                            .entry(*validator)
                            .or_insert_with(HashMap::new);

                        let entry = dels.entry(*delegator).or_insert(0);
                        *entry += *amount;

                        // 3. QV update
                        self.update_qv_weight(delegator);
                        self.update_validator_qv_weight(validator);

                        println!(
                            "💎 Validator self-stake recorded: {} staked {}",
                            validator, amount
                        );
                    } else {
                        // ✅ delegator eksternal
                        self.register_delegator_stake(delegator, validator, *amount)?;
                    }

                } else {
                    // Unbond: determine if it's self-unbond or delegator withdrawal
                    if delegator == validator {
                        // Self-unbond
                        self.unbond(delegator, validator, *amount)?;
                    } else {
                        // Delegator withdrawal
                        self.withdraw_delegator_stake(delegator, validator, *amount)?;
                    }
                }
                (0, None)
            }

            TxPayload::Unstake { delegator, validator, amount, .. } => {
                self.unbond(delegator, validator, *amount)?;
                (0, None)
            }
            TxPayload::ClaimReward { receipt, fee, gas_limit: _, .. } => {
                // ════════════════════════════════════════════════════════════
                // CLAIMREWARD EXECUTION (14C.B — CONSENSUS-CRITICAL)
                // ════════════════════════════════════════════════════════════
                //
                // Bridge: menggunakan komponen baru dari claim_reward_handler
                // tanpa full ReceiptV1 conversion (yang belum possible karena
                // ResourceReceipt belum punya semua field ReceiptV1).
                //
                // Komponen baru yang digunakan:
                //   - AntiSelfDealingCheck (3-level detection)
                //   - RewardDistribution (clean 70/20/10 split)
                //   - receipt_dedup_tracker.mark_claimed (atomic dedup)
                //   - PendingChallenge (Compute routing)
                //   - execute_reward_distribution pattern
                //
                // MIGRATION PATH:
                // Ketika TxPayload::ClaimReward migrate ke ReceiptV1,
                // seluruh block ini diganti dengan single call ke:
                //   claim_reward_handler::handle_claim_reward(&claim, self, time, epoch)
                //
                // ════════════════════════════════════════════════════════════

                use dsdn_common::claim_validation::RewardDistribution;
                use dsdn_common::challenge_state::PendingChallenge;
                use crate::receipt::ResourceType;

                // ──────────────────────────────────────────────────────────
                // STEP 1 — VERIFY (read-only, legacy path)
                // ──────────────────────────────────────────────────────────
                // Uses old verify_receipt for Ed25519 signature validation.
                // Will be replaced by verify_receipt_v1() after ReceiptV1 migration.
                self.verify_receipt(&receipt, &sender)
                    .map_err(|e| anyhow!("receipt verification failed: {:?}", e))?;

                let reward_base = receipt.reward_base;
                let node_address = receipt.node_address;

                // ──────────────────────────────────────────────────────────
                // STEP 2 — ANTI-SELF-DEALING (read-only, NEW component)
                // ──────────────────────────────────────────────────────────
                // 3-level detection via AntiSelfDealingCheck:
                //   Level 1: Direct address match (node == submitter)
                //   Level 2: Owner match (operator == submitter)
                //   Level 3: Wallet affinity (stub v1)
                //
                // Also preserves legacy flag check for backward compat.
                let legacy_flag = receipt.anti_self_dealing_flag;

                // Lookup operator address via node_address → service_node_index
                // (service_node_index maps node_id → operator, but for legacy
                //  receipts we check node_address directly)
                //
                // Legacy bridge: direct comparison instead of AntiSelfDealingCheck
                // because chain Address (newtype) ≠ common Address ([u8; 20]).
                // Full 3-level AntiSelfDealingCheck is used in handle_claim_reward()
                // after ReceiptV1 migration.
                let new_detection = node_address == sender;

                let is_self_dealing = legacy_flag || new_detection;

                // ──────────────────────────────────────────────────────────
                // STEP 3 — COMPUTE DISTRIBUTION (pure, NEW component)
                // ──────────────────────────────────────────────────────────
                // Replaces old manual (reward_base * 70) / 100 arithmetic.
                // RewardDistribution guarantees sum == reward_base (treasury
                // absorbs rounding remainder).
                let distribution = if is_self_dealing {
                    RewardDistribution::with_anti_self_dealing(reward_base)
                } else {
                    RewardDistribution::compute(reward_base)
                };

                // ══════════════════════════════ MUTATION BOUNDARY ══════════════════════════════
                // Everything above is read-only. Everything below mutates state.
                // mark_claimed is the atomic gate.

                // ──────────────────────────────────────────────────────────
                // STEP 4 — MARK CLAIMED (atomic gate, NEW component)
                // ──────────────────────────────────────────────────────────
                // Uses new receipt_dedup_tracker (returns Result, unlike old
                // mark_receipt_claimed which was idempotent void).
                // If this fails → no state mutated.
                //
                // Also mark in legacy claimed_receipts for backward compat.
                let receipt_hash = {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(receipt.receipt_id.as_bytes());
                    h
                };
                self.receipt_dedup_tracker.mark_claimed(receipt_hash)
                    .map_err(|e| anyhow!("receipt dedup failed: {:?}", e))?;
                // Legacy: keep old claimed_receipts in sync
                self.mark_receipt_claimed(receipt.receipt_id.clone());

                // ──────────────────────────────────────────────────────────
                // STEP 5 — ROUTE BY RECEIPT TYPE (NEW: Storage vs Compute)
                // ──────────────────────────────────────────────────────────
                let claim_result_events = match receipt.resource_type {
                    ResourceType::Storage => {
                        // Immediate reward distribution (NEW pattern).
                        // Node reward → node balance
                        // Validator reward → reward_pool (proposer collects later)
                        // Treasury reward → treasury_balance
                        if distribution.node_reward > 0 {
                            *self.balances.entry(node_address).or_insert(0) += distribution.node_reward;
                            *self.node_earnings.entry(node_address).or_insert(0) += distribution.node_reward;
                        }
                        self.reward_pool = self.reward_pool.saturating_add(distribution.validator_reward);
                        self.treasury_balance = self.treasury_balance.saturating_add(distribution.treasury_reward);

                        // Counter updates (saturating — infallible).
                        self.total_receipts_claimed = self.total_receipts_claimed.saturating_add(1);
                        self.total_rewards_distributed = self.total_rewards_distributed
                            .saturating_add(reward_base);

                        vec![
                            "claim_reward_executed".to_string(),
                            "result=ImmediateReward".to_string(),
                            format!("reward_base={}", reward_base),
                            format!("node_share={}", distribution.node_reward),
                            format!("validator_share={}", distribution.validator_reward),
                            format!("treasury_share={}", distribution.treasury_reward),
                            format!("anti_self_dealing={}", is_self_dealing),
                        ]
                    }
                    ResourceType::Compute => {
                        // Challenge period — reward deferred (NEW).
                        let current_time = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);

                        // Use receipt_id bytes as node_id placeholder (legacy bridge).
                        // Real node_id will be available after ReceiptV1 migration.
                        let node_id_placeholder = receipt_hash;

                        let challenge = PendingChallenge::new(
                            receipt_hash,
                            node_id_placeholder,
                            distribution,
                            current_time,
                        );
                        let challenge_end = challenge.challenge_end;

                        self.pending_challenges.insert(receipt_hash, challenge);

                        // Counter update: receipts_claimed YES, rewards_distributed NO.
                        // Rewards distributed only when challenge period ends clean.
                        self.total_receipts_claimed = self.total_receipts_claimed.saturating_add(1);

                        vec![
                            "claim_reward_executed".to_string(),
                            "result=ChallengePeriodStarted".to_string(),
                            format!("reward_base={}", reward_base),
                            format!("challenge_end={}", challenge_end),
                            format!("pending_node_share={}", distribution.node_reward),
                            format!("pending_validator_share={}", distribution.validator_reward),
                            format!("pending_treasury_share={}", distribution.treasury_reward),
                            format!("anti_self_dealing={}", is_self_dealing),
                        ]
                    }
                };

                // ──────────────────────────────────────────────────────────
                // STEP 6 — FEE DEDUCTION (unchanged from old logic)
                // ──────────────────────────────────────────────────────────
                // Transaction fee is SEPARATE from reward distribution.
                let gas_used = FIXED_GAS_CLAIM;
                let gas_cost = gas_used as u128;
                let total_fee = *fee + gas_cost;

                let sender_bal = self.balances.entry(sender).or_insert(0);
                if *sender_bal < total_fee {
                    // NOTE: mark_claimed already happened. This is acceptable
                    // because insufficient fee should have been caught by
                    // validate_stateful before apply_payload. If we reach here,
                    // it's a protocol-level inconsistency.
                    anyhow::bail!("insufficient balance for ClaimReward fee");
                }
                *sender_bal -= total_fee;

                // Fee 100% ke validator/proposer
                *self.balances.entry(*miner_addr).or_insert(0) += total_fee;

                // Increment nonce sender
                self.increment_nonce(&sender);

                return Ok((gas_used, claim_result_events));
            }

            TxPayload::ValidatorRegistration { from, pubkey, min_stake, .. } => {
                // === STAKE REQUIREMENT ENFORCEMENT (13.7.C + 13.8.A) ===
                
                // 1. Cek minimum stake requirement (using tokenomics constant)
                if *min_stake < crate::tokenomics::VALIDATOR_MIN_STAKE {
                    anyhow::bail!(
                        "validator stake too low: minimum {} required, got {}",
                        crate::tokenomics::VALIDATOR_MIN_STAKE,
                        min_stake
                    );
                }
                
                // 2. Cek balance sender cukup untuk min_stake
                let sender_balance = self.get_balance(from);
                if sender_balance < *min_stake {
                    anyhow::bail!(
                        "insufficient balance for validator registration: need {}, have {}",
                        min_stake,
                        sender_balance
                    );
                }
                
                // 3. Cek tidak sudah jadi validator
                if self.validators.contains_key(from) {
                    anyhow::bail!("address already registered as validator");
                }
                
                // 4. Deposit ke validator_stakes (13.8.A - EXPLICIT SEPARATION)
                // Ini BERBEDA dari bond() - ini adalah stake validator sendiri
                self.deposit_validator_stake(from, *min_stake)?;
                
                // 5. Register to legacy validators map
                self.validators.insert(*from, Validator {
                    address: *from,
                    stake: *min_stake,
                    pubkey: pubkey.clone(),
                    active: true,
                });
                
                // 6. Register ke ValidatorSet (DPoS Hybrid)
                let validator_info = ValidatorInfo::new(
                    *from,
                    pubkey.clone(),
                    *min_stake,
                    None, // moniker bisa ditambah via governance nanti
                );
                self.validator_set.add_validator(validator_info);
                
                // 7. Track self-delegation in delegations map (for QV)
                let validator_delegations = self.delegations.entry(*from).or_insert_with(HashMap::new);
                validator_delegations.insert(*from, *min_stake);
                
                println!("✅ Validator registered: {} with stake {}", from, min_stake);
                (0, None)
            }

            TxPayload::RegisterServiceNode { from, node_id, class, tls_fingerprint, identity_proof_sig: _, .. } => {
                // ════════════════════════════════════════════════════════════════
                // SERVICE NODE REGISTRATION (14B.13 — CONSENSUS-CRITICAL)
                // ════════════════════════════════════════════════════════════════
                // Atomic: validate → lock stake → create record → insert registry
                // ════════════════════════════════════════════════════════════════

                // 1. Determine required stake based on NodeClass
                let required_stake = min_stake_for_node_class(class);

                // 2. Check sender balance >= required stake
                let sender_balance = self.get_balance(from);
                if sender_balance < required_stake {
                    anyhow::bail!(
                        "insufficient balance for service node registration: need {}, have {}",
                        required_stake,
                        sender_balance
                    );
                }

                // 3. Check not already registered as service node
                if self.service_nodes.contains_key(from) {
                    anyhow::bail!("address already registered as service node");
                }

                // 4. Validate and convert node_id to [u8; 32]
                if node_id.len() != 32 {
                    anyhow::bail!("node_id must be exactly 32 bytes, got {}", node_id.len());
                }
                let mut nid = [0u8; 32];
                nid.copy_from_slice(node_id);

                // 5. Check node_id not already used by another operator
                if self.service_node_index.contains_key(&nid) {
                    anyhow::bail!("node_id already registered by another operator");
                }

                // 6. Lock stake: deduct from liquid balance, add to locked
                let sender_bal = self.balances.entry(*from).or_insert(0);
                *sender_bal -= required_stake;
                *self.locked.entry(*from).or_insert(0) += required_stake;

                // 7. Build ServiceNodeRecord
                let record = ServiceNodeRecord {
                    operator_address: *from,
                    node_id: nid,
                    class: *class,
                    status: NodeStatus::Pending,
                    staked_amount: required_stake,
                    registered_height: 0,
                    last_status_change_height: 0,
                    cooldown: None,
                    tls_fingerprint: if tls_fingerprint.is_empty() {
                        None
                    } else if tls_fingerprint.len() == 32 {
                        let mut fp = [0u8; 32];
                        fp.copy_from_slice(tls_fingerprint);
                        Some(fp)
                    } else {
                        anyhow::bail!(
                            "tls_fingerprint must be exactly 32 bytes or empty, got {}",
                            tls_fingerprint.len()
                        );
                    },
                    metadata: HashMap::new(),
                };

                // 8. Insert into registry (atomic: service_nodes + service_node_index)
                self.register_service_node(record)
                    .map_err(|e| anyhow::anyhow!("service node registration failed: {}", e))?;

                println!("✅ Service node registered: {} class={:?} stake={}", from, class, required_stake);
                (0, None)
            }

            TxPayload::GovernanceAction { from, action, fee: _, nonce: _, gas_limit: _ } => {
                // ════════════════════════════════════════════════════════════════════════════
                // GOVERNANCE ACTION EXECUTION (13.13.7 — Integration)
                // ════════════════════════════════════════════════════════════════════════════
                // Payload governance diproses berdasarkan action type.
                // Event logging ditambahkan untuk setiap aksi yang berhasil.
                // Preview di-generate setelah CreateProposal berhasil.
                // Bootstrap mode check diterapkan di FinalizeProposal.
                // ════════════════════════════════════════════════════════════════════════════

                // Get current timestamp (menggunakan epoch timestamp untuk consistency)
                let current_timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                match action {
                    // ─────────────────────────────────────────────────────────
                    // 1. CREATE PROPOSAL
                    // ─────────────────────────────────────────────────────────
                    GovernanceActionType::CreateProposal { proposal_type, title, description } => {
                        // Execute create_proposal
                        let proposal_id = self.create_proposal(
                            *from,
                            proposal_type.clone(),
                            title.clone(),
                            description.clone(),
                            current_timestamp,
                        ).map_err(|e| anyhow!("create_proposal failed: {:?}", e))?;

                        println!("🏛️ Proposal created: #{}", proposal_id);

                        // Log ProposalCreated event
                        self.governance_events.push(GovernanceEvent {
                            event_type: GovernanceEventType::ProposalCreated,
                            proposal_id: Some(proposal_id),
                            actor: *from,
                            timestamp: current_timestamp,
                            details: format!("Proposal #{} created: {}", proposal_id, title),
                        });

                        // Generate preview (READ-ONLY, tidak mengubah state)
                        // Jika gagal, log error tapi JANGAN rollback proposal
                        match self.generate_proposal_preview(proposal_id) {
                            Ok(_preview) => {
                                // Log PreviewGenerated event
                                self.governance_events.push(GovernanceEvent {
                                    event_type: GovernanceEventType::PreviewGenerated,
                                    proposal_id: Some(proposal_id),
                                    actor: *from,
                                    timestamp: current_timestamp,
                                    details: format!("Preview generated for proposal #{}", proposal_id),
                                });
                                println!("   ✅ Preview generated for proposal #{}", proposal_id);
                            }
                            Err(e) => {
                                // Preview gagal, log error tapi proposal tetap valid
                                println!("   ⚠️ Preview generation failed: {:?} (proposal remains valid)", e);
                            }
                        }

                        // Enforce retention policy
                        self.enforce_governance_events_retention();
                    }

                    // ─────────────────────────────────────────────────────────
                    // 2. CAST VOTE
                    // ─────────────────────────────────────────────────────────
                    GovernanceActionType::CastVote { proposal_id, vote } => {
                        // Execute cast_vote
                        self.cast_vote(
                            *from,
                            *proposal_id,
                            vote.clone(),
                            current_timestamp,
                        ).map_err(|e| anyhow!("cast_vote failed: {:?}", e))?;

                        println!("🗳️ Vote cast on proposal #{}: {:?}", proposal_id, vote);

                        // Log VoteCast event
                        self.governance_events.push(GovernanceEvent {
                            event_type: GovernanceEventType::VoteCast,
                            proposal_id: Some(*proposal_id),
                            actor: *from,
                            timestamp: current_timestamp,
                            details: format!("Vote {:?} cast on proposal #{}", vote, proposal_id),
                        });

                        // Enforce retention policy
                        self.enforce_governance_events_retention();
                    }

                    // ─────────────────────────────────────────────────────────
                    // 3. FINALIZE PROPOSAL
                    // ─────────────────────────────────────────────────────────
                    GovernanceActionType::FinalizeProposal { proposal_id } => {
                        // Execute finalize_proposal
                        self.finalize_proposal(*proposal_id, current_timestamp)
                            .map_err(|e| anyhow!("finalize_proposal failed: {:?}", e))?;

                        // Get finalized status
                        let status = self.proposals.get(proposal_id)
                            .map(|p| p.status)
                            .unwrap_or(ProposalStatus::Active);

                        println!("✅ Proposal #{} finalized: {:?}", proposal_id, status);

                        // Log ProposalFinalized event
                        self.governance_events.push(GovernanceEvent {
                            event_type: GovernanceEventType::ProposalFinalized,
                            proposal_id: Some(*proposal_id),
                            actor: *from,
                            timestamp: current_timestamp,
                            details: format!("Proposal #{} finalized with status {:?}", proposal_id, status),
                        });

                        // ════════════════════════════════════════════════════════════
                        // BOOTSTRAP MODE CHECK — EXECUTION BLOCKING (13.13.3)
                        // ════════════════════════════════════════════════════════════
                        // Jika proposal Passed DAN bootstrap_mode == true:
                        // - TIDAK ada eksekusi
                        // - Log ExecutionAttemptBlocked
                        // ════════════════════════════════════════════════════════════
                        if status == ProposalStatus::Passed && self.governance_config.bootstrap_mode {
                            println!("   ⚠️ BOOTSTRAP MODE: Execution blocked for proposal #{}", proposal_id);
                            
                            // Log ExecutionAttemptBlocked event
                            self.governance_events.push(GovernanceEvent {
                                event_type: GovernanceEventType::ExecutionAttemptBlocked,
                                proposal_id: Some(*proposal_id),
                                actor: Address::from_bytes([0u8; 20]), // System guard
                                timestamp: current_timestamp,
                                details: format!(
                                    "Execution blocked for proposal #{}: bootstrap mode active (status={:?})",
                                    proposal_id, status
                                ),
                            });
                        }

                        // Enforce retention policy
                        self.enforce_governance_events_retention();
                    }

                    // ─────────────────────────────────────────────────────────
                    // 4. FOUNDATION VETO
                    // ─────────────────────────────────────────────────────────
                    GovernanceActionType::FoundationVeto { proposal_id } => {
                        // Execute veto_proposal
                        self.veto_proposal(*from, *proposal_id)
                            .map_err(|e| anyhow!("veto_proposal failed: {:?}", e))?;

                        println!("⛔ Proposal #{} vetoed by Foundation", proposal_id);

                        // Log ProposalVetoed event
                        self.governance_events.push(GovernanceEvent {
                            event_type: GovernanceEventType::ProposalVetoed,
                            proposal_id: Some(*proposal_id),
                            actor: *from,
                            timestamp: current_timestamp,
                            details: format!("Proposal #{} vetoed by Foundation", proposal_id),
                        });

                        // Enforce retention policy
                        self.enforce_governance_events_retention();
                    }

                    // ─────────────────────────────────────────────────────────
                    // 5. FOUNDATION OVERRIDE
                    // ─────────────────────────────────────────────────────────
                    GovernanceActionType::FoundationOverride { proposal_id, new_status } => {
                        // Get old status before override
                        let old_status = self.proposals.get(proposal_id)
                            .map(|p| p.status)
                            .unwrap_or(ProposalStatus::Active);

                        // Execute override_proposal_result
                        self.override_proposal_result(*from, *proposal_id, new_status.clone())
                            .map_err(|e| anyhow!("override_proposal_result failed: {:?}", e))?;

                        println!("🔄 Proposal #{} overridden: {:?} → {:?}", proposal_id, old_status, new_status);

                        // Log ProposalOverridden event
                        self.governance_events.push(GovernanceEvent {
                            event_type: GovernanceEventType::ProposalOverridden,
                            proposal_id: Some(*proposal_id),
                            actor: *from,
                            timestamp: current_timestamp,
                            details: format!(
                                "Proposal #{} overridden from {:?} to {:?}",
                                proposal_id, old_status, new_status
                            ),
                        });

                        // Enforce retention policy
                        self.enforce_governance_events_retention();
                    }
                }

                (0, None)
            }
            TxPayload::Custom { .. } => (0, None),
        };

        // ============================================================
        // GAS CALCULATION via internal_gas::compute_gas_for_payload (13.9)
        // ============================================================
        // Gas dihitung melalui internal_gas::compute_gas_for_payload,
        // menghasilkan GasBreakdown yang digunakan untuk compute fee
        // dan dicatat dalam receipt.
        // ============================================================
        
        // Determine service_node for gas calculation
        let service_node: Option<Address> = match &env.payload {
            TxPayload::StorageOperationPayment { to_node, .. } => Some(*to_node),
            TxPayload::ComputeExecutionPayment { to_node, .. } => Some(*to_node),
            _ => None,
        };
        
        // Compute gas breakdown using pure function
        let gas_info = internal_gas::compute_gas_for_payload(env, service_node, self);
        let gas_used = gas_info.total_gas_used;
        let gas_cost = gas_info.total_fee_cost;

        // Ambil fee dari payload
        let fee = match &env.payload {
            TxPayload::Transfer { fee, .. } => *fee,
            TxPayload::Stake { fee, .. } => *fee,
            TxPayload::Unstake { fee, .. } => *fee,
            TxPayload::ClaimReward { fee, .. } => *fee,
            TxPayload::StorageOperationPayment { fee, .. } => *fee,
            TxPayload::ComputeExecutionPayment { fee, .. } => *fee,
            TxPayload::ValidatorRegistration { fee, .. } => *fee,
            TxPayload::RegisterServiceNode { fee, .. } => *fee,
            TxPayload::GovernanceAction { fee, .. } => *fee,
            TxPayload::Custom { fee, .. } => *fee,
        };

        let total_deduct = amount_to_transfer + fee + gas_cost;
        println!("🔎 TX COSTS: amount={}, fee={}, gas_used={}, gas_cost={}, total_deduct={}",
                 amount_to_transfer, fee, gas_used, gas_cost, total_deduct);
        println!("   📊 GasBreakdown: base={}, data={}, compute={}, multiplier={}",
                 gas_info.base_op_cost, gas_info.data_cost, gas_info.compute_cost, gas_info.node_multiplier);

        let sender_bal = self.balances.entry(sender).or_insert(0);
        if *sender_bal < total_deduct {
            println!("   ❌ Insufficient funds: sender_balance={} needed={}", *sender_bal, total_deduct);
            anyhow::bail!("insufficient balance for tx execution");
        }
        println!("   ⬇️ Deducting {} from sender (before={})", total_deduct, *sender_bal);
        *sender_bal -= total_deduct;
        println!("   ✅ Sender after deduct = {}", *sender_bal);

        // === FEE ALLOCATION RULES (DSDN) ===
        // Distribute fee + gas_cost based on ResourceClass
        let total_fee = fee + gas_cost;

        // ============================================================
        // ANTI SELF-DEALING RULE (13.7.G)
        // ============================================================
        // Jika sender == proposer, fee dialihkan ke treasury
        // Validator tidak boleh mendapat reward dari tx miliknya sendiri
        if sender == *miner_addr {
            println!("⚠️  Anti self-dealing: sender == proposer, fee → treasury");
            self.treasury_balance += total_fee;
            
            // CRITICAL: Transfer amount HARUS dikirim ke tujuan
            if let Some(to) = to_opt {
                println!("   💸 Transferring {} to recipient {}", amount_to_transfer, to);
                *self.balances.entry(to).or_insert(0) += amount_to_transfer;
            }
            
            // Increment nonce sender
            self.increment_nonce(&sender);
            
            return Ok((gas_used, vec![
                "anti_self_dealing_applied".to_string(),
                format!("fee_to_treasury={}", total_fee),
                format!("amount_transferred={}", amount_to_transfer),
            ]));
        }
        
        // ============================================================
        // FEE ALLOCATION (Blueprint 70/20/10)
        // ============================================================
        // Storage/Compute: Node 70%, Validator 20%, Treasury 10%
        // Transfer/Governance: Validator 100%
        // Anti-self-dealing node: jika service_node == sender → node_share ke treasury
        // ============================================================
        let resource_class = env.payload.resource_class();
        
        use crate::tx::ResourceClass;
        use crate::tokenomics::calculate_fee_by_resource_class;
        
        let fee_split = calculate_fee_by_resource_class(total_fee, &resource_class, service_node, &sender);
        
        match resource_class {
            ResourceClass::Transfer => {
                // 100% to validator (proposer)
                *self.balances.entry(*miner_addr).or_insert(0) += fee_split.validator_share;
                println!("💰 Transfer Fee: {} → validator {}", fee_split.validator_share, miner_addr);
            }
            ResourceClass::Governance => {
                // Blueprint: 100% validator
                *self.balances.entry(*miner_addr).or_insert(0) += fee_split.validator_share;
                self.treasury_balance += fee_split.treasury_share;
                println!("💰 Governance Fee: total={}, validator={}, treasury={}",
                         total_fee, fee_split.validator_share, fee_split.treasury_share);
            }
            ResourceClass::Storage => {
                // Blueprint 70/20/10: Node 70%, Validator 20%, Treasury 10%
                // (anti-self-dealing sudah dihandle di calculate_fee_by_resource_class)
                if let Some(node_addr) = service_node {
                    if fee_split.node_share > 0 {
                        *self.balances.entry(node_addr).or_insert(0) += fee_split.node_share;
                        *self.node_earnings.entry(node_addr).or_insert(0) += fee_split.node_share;
                        println!("💾 Storage Fee: node_share={} → storage_node {}", fee_split.node_share, node_addr);
                    }
                } else {
                    self.storage_fee_pool += fee_split.node_share;
                    println!("💾 Storage Fee: {} → storage_fee_pool (no node)", fee_split.node_share);
                }
                *self.balances.entry(*miner_addr).or_insert(0) += fee_split.validator_share;
                self.treasury_balance += fee_split.treasury_share;
                println!("   validator_share={} → {}, treasury_share={}", 
                         fee_split.validator_share, miner_addr, fee_split.treasury_share);
            }
            ResourceClass::Compute => {
                // Blueprint 70/20/10: Node 70%, Validator 20%, Treasury 10%
                // (anti-self-dealing sudah dihandle di calculate_fee_by_resource_class)
                if let Some(node_addr) = service_node {
                    if fee_split.node_share > 0 {
                        *self.balances.entry(node_addr).or_insert(0) += fee_split.node_share;
                        *self.node_earnings.entry(node_addr).or_insert(0) += fee_split.node_share;
                        println!("🖥️ Compute Fee: node_share={} → compute_node {}", fee_split.node_share, node_addr);
                    }
                } else {
                    self.compute_fee_pool += fee_split.node_share;
                    println!("🖥️ Compute Fee: {} → compute_fee_pool (no node)", fee_split.node_share);
                }
                *self.balances.entry(*miner_addr).or_insert(0) += fee_split.validator_share;
                self.treasury_balance += fee_split.treasury_share;
                println!("   validator_share={} → {}, treasury_share={}", 
                         fee_split.validator_share, miner_addr, fee_split.treasury_share);
            }
        }

        // Transfer amount jika ada tujuan (payment untuk service, TERPISAH dari fee)
        if let Some(to) = to_opt {
            *self.balances.entry(to).or_insert(0) += amount_to_transfer;
        }

        // Increment nonce sender
        self.increment_nonce(&sender);

        // Events dengan gas_breakdown dan fee_split untuk audit
        let mut events = match &env.payload {
            TxPayload::GovernanceAction { .. } => vec!["governance_action_executed".to_string()],
            _ => vec![],
        };
        
        // Tambahkan gas dan fee info ke events
        events.push(format!("gas_used={}", gas_used));
        events.push(format!("gas_breakdown={{base:{},data:{},compute:{},mult:{}}}", 
                           gas_info.base_op_cost, gas_info.data_cost, gas_info.compute_cost, gas_info.node_multiplier));
        events.push(format!("fee_split={{node:{},val:{},tre:{}}}", 
                           fee_split.node_share, fee_split.validator_share, fee_split.treasury_share));

Ok((gas_used, events))
    }

    // ════════════════════════════════════════════════════════════════════════════
    // GOVERNANCE EVENT RETENTION (13.13.7)
    // ════════════════════════════════════════════════════════════════════════════

    /// Enforce retention policy untuk governance events.
    ///
    /// Maksimum 1000 events (MAX_GOVERNANCE_EVENTS).
    /// Jika melebihi, hapus event tertua (FIFO).
    fn enforce_governance_events_retention(&mut self) {
        use super::internal_governance::MAX_GOVERNANCE_EVENTS;
        
        while self.governance_events.len() > MAX_GOVERNANCE_EVENTS {
            self.governance_events.remove(0);
        }
    }
}