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
use dsdn_common::gating::{NodeClass, NodeStatus};
use crate::gating::ServiceNodeRecord;

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
const SERVICE_NODE_MIN_STAKE_REGULAR: u128 = 500;
const SERVICE_NODE_MIN_STAKE_DATACENTER: u128 = 5_000;
#[allow(dead_code)]
const FIXED_GAS_SERVICE_NODE_REG: u64 = 50_000;

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
            TxPayload::GovernanceAction { from, .. } => from,
            TxPayload::RegisterServiceNode { from, .. } => from,
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
                TxPayload::GovernanceAction { from, .. } => *from,
                TxPayload::RegisterServiceNode { from, .. } => *from,
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
                // CLAIMREWARD EXECUTION (13.10 - CONSENSUS-CRITICAL)
                // ════════════════════════════════════════════════════════════
                // ClaimReward dieksekusi secara terpisah dari flow normal
                // karena reward distribution berbeda dari fee allocation.
                // ════════════════════════════════════════════════════════════

                // 1. Verifikasi receipt (signature, double-claim, node match, anti-self-dealing, timestamp)
                self.verify_receipt(&receipt, &sender)
                    .map_err(|e| anyhow!("receipt verification failed: {:?}", e))?;

                // 2. Ambil data dari receipt
                let reward_base = receipt.reward_base;
                let node_address = receipt.node_address;

                // 3. Hitung distribusi FIXED 70/20/10
                let node_share = (reward_base * 70) / 100;
                let validator_share = (reward_base * 20) / 100;
                let mut treasury_share = reward_base - node_share - validator_share;
                let mut final_node_share = node_share;

                // 4. Apply ANTI-SELF-DEALING rule
                // Jika anti_self_dealing_flag == true ATAU node_address == sender
                // MAKA node_share dialihkan ke treasury
                if receipt.anti_self_dealing_flag || node_address == sender {
                    treasury_share += final_node_share;
                    final_node_share = 0;
                }

                // 5. Kredit saldo node (hanya jika ada share)
                if final_node_share > 0 {
                    *self.balances.entry(node_address).or_insert(0) += final_node_share;
                }

                // 6. Kredit saldo proposer/miner (validator_share)
                *self.balances.entry(*miner_addr).or_insert(0) += validator_share;

                // 7. Kredit treasury
                self.treasury_balance += treasury_share;

                // 8. Update node_earnings (hanya jika ada share)
                if final_node_share > 0 {
                    *self.node_earnings.entry(node_address).or_insert(0) += final_node_share;
                }

                // 9. Tandai receipt sebagai claimed (anti double-claim)
                self.mark_receipt_claimed(receipt.receipt_id.clone());

                // 10. Process transaction fee (terpisah dari reward)
                let gas_used = FIXED_GAS_CLAIM;
                let gas_cost = gas_used as u128;
                let total_fee = *fee + gas_cost;

                // Deduct fee dari sender
                let sender_bal = self.balances.entry(sender).or_insert(0);
                if *sender_bal < total_fee {
                    anyhow::bail!("insufficient balance for ClaimReward fee");
                }
                *sender_bal -= total_fee;

                // Fee 100% ke validator (seperti Governance)
                *self.balances.entry(*miner_addr).or_insert(0) += total_fee;

                // Increment nonce sender
                self.increment_nonce(&sender);

                // Return early (skip normal fee allocation flow)
                return Ok((gas_used, vec![
                    "claim_reward_executed".to_string(),
                    format!("reward_base={}", reward_base),
                    format!("node_share={}", final_node_share),
                    format!("validator_share={}", validator_share),
                    format!("treasury_share={}", treasury_share),
                    format!("anti_self_dealing={}", receipt.anti_self_dealing_flag || node_address == sender),
                ]));
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

            // ─────────────────────────────────────────────────────────────
            // REGISTER SERVICE NODE (14B.13)
            // ─────────────────────────────────────────────────────────────
            // Atomic sequence:
            // 1. Compute min_stake from class
            // 2. Validate balance >= min_stake
            // 3. Validate not already registered
            // 4. Lock stake (deduct from balance)
            // 5. Create ServiceNodeRecord (status = Pending)
            // 6. Insert into registry via register_service_node
            //
            // If ANY step fails, no state is modified (all validations
            // before mutations, register_service_node validates before insert).
            //
            // NOTE: registered_height and last_status_change_height are set to 0
            // because ChainState does not track current block height.
            // This matches ValidatorRegistration which also lacks height context.
            // Height will be set when block processing pipeline provides it.
            // ─────────────────────────────────────────────────────────────
            TxPayload::RegisterServiceNode {
                from, node_id, class, tls_fingerprint, identity_proof_sig: _, ..
            } => {
                // 1. Compute min_stake from class
                let min_stake: u128 = match class {
                    NodeClass::DataCenter => SERVICE_NODE_MIN_STAKE_DATACENTER,
                    _ => SERVICE_NODE_MIN_STAKE_REGULAR,
                };

                // 2. Validate balance >= min_stake
                let sender_balance = self.get_balance(from);
                if sender_balance < min_stake {
                    anyhow::bail!(
                        "insufficient balance for service node registration: need {}, have {}",
                        min_stake, sender_balance
                    );
                }

                // 3. Validate not already registered as service node
                if self.service_nodes.contains_key(from) {
                    anyhow::bail!("address already registered as service node");
                }

                // 4. Lock stake: deduct min_stake from sender balance
                //    This MUST happen before register_service_node to ensure
                //    balance consistency. If register fails after this point,
                //    the bail! will propagate and apply_payload returns Err,
                //    meaning this transaction is rejected entirely (no state persisted).
                let sender_bal = self.balances.entry(*from).or_insert(0);
                if *sender_bal < min_stake {
                    anyhow::bail!("insufficient balance to lock service node stake");
                }
                *sender_bal -= min_stake;

                // Track locked stake
                *self.locked.entry(*from).or_insert(0) += min_stake;

                // 5. Create ServiceNodeRecord
                let record = ServiceNodeRecord {
                    operator_address: *from,
                    node_id: *node_id,
                    class: class.clone(),
                    status: NodeStatus::Pending,
                    staked_amount: min_stake,
                    registered_height: 0,
                    last_status_change_height: 0,
                    cooldown: None,
                    tls_fingerprint: Some(*tls_fingerprint),
                    metadata: HashMap::new(),
                };

                // 6. Register in service node registry (validates uniqueness atomically)
                self.register_service_node(record)
                    .map_err(|e| anyhow::anyhow!("service node registration failed: {}", e))?;

                println!(
                    "✅ Service node registered: operator={} node_id={} class={:?} stake={}",
                    from, hex::encode(node_id), class, min_stake
                );

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
            TxPayload::GovernanceAction { fee, .. } => *fee,
            TxPayload::RegisterServiceNode { fee, .. } => *fee,
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