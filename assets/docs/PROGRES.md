1 - 14.2b.2 = Finished
focus on stage which is being worked on


[Active_stage]
## Stage 14C.A — Receipt Foundation & Chain Validation

**Objective:** Define economic data structures (ExecutionCommitment, ReceiptV1),
implementing chain-side validation, and preparing a coordinator for threshold-sign receipt.

**Crates involved:** `proto`, `common`, `chain`, `coordinator`

### Scope

1. **`proto`** — Definition of protobuf/message types:
   - Add message `ExecutionCommitment` (workload_id, input_hash, output_hash,
     state_root_before, state_root_after, execute_trace_merkle_root).
   - Add message `ReceiptV1` (workload_id, node_id, usage_proof_hash,
     execution_commitment, coordinator_threshold_signature, node_signature,
     submitter_address).
   - Add `ClaimReward` request/response message.
   - Add `FraudProofChallenge` message (placeholder, no logic yet).

2. **`common`** — Shared types and utilities:
   - Type aliases and helpers for `WorkloadId`, `UsageProofHash`, `ExecutionCommitment`.
   - Deterministic hashing function for execution commitment fields.
   - Economic constants: distribution ratio (70/20/10), challenge period duration (1 hour).
   - Anti-self-dealing helper: function `is_self_dealing(node_owner, submitter)`.

3. **`chain`** — On-chain validation and reward logic:
   - Implementation of `ClaimReward` transaction handler.
   - Receipt validation: threshold signature valid, stake sufficient,
     no duplicate receipt, anti-self-dealing check.
   - Validate execution commitment: hash consistency, fields non-empty.
   - Reward distribution logic: 70% nodes, 20% validators, 10% treasury (fixed, no burn).
   - Challenge period state: compute receipts enter pending state for 1 hour,
     storage receipts directly distribute.
   - Reject logic: duplicate receipt, self-dealing, invalid signature, invalid commitment.

4. **`coordinator`** — Threshold signing receipt:
   - Coordinator receives usage proof + execution commitment from node.
   - Basic verification: registered workload, eligible nodes, valid proof format.
   - Threshold-sign receipt uses FROST (calls TSS, but TSS integration
     done in 14C.C — here just define interface/trait).
   - Return signed `ReceiptV1` to the node to submit to the chain.

### Completion Criteria 14C.A

- All proto messages are defined and can be serialized/deserialized.
- The chain can receive a ClaimReward, complete validation, and distribute the reward (with a mock signature for testing).
- The coordinator has a flow: receive proof → validate → sign receipt (mock TSS).
- The anti-self-dealing test passes.
- The duplicate receipt rejection test passes.
- The challenge period state for compute receipts is recorded in the chain.