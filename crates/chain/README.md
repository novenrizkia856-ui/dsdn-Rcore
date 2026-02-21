# DSDN Chain

Core blockchain implementation for **Nusantara Chain** — the settlement and governance layer of the DSDN (Distributed Storage and Data Network) ecosystem.

## Overview

The `chain` crate provides the complete blockchain infrastructure for DSDN, implementing a Delegated Proof of Stake (DPoS) consensus with Quadratic Voting governance. It handles all on-chain operations including transactions, staking, governance proposals, validator management, and economic controls.

Nusantara Chain is designed as a **semi-decentralized** blockchain where the data and compute plane is permissionless (anyone can run a node), while the governance and compliance plane is permissioned through an identity-verified validator set.

### Key Specifications

| Specification | Value |
|---------------|-------|
| Native Token | $NUSA |
| Max Supply | 300,000,000 NUSA |
| Hash Algorithm | SHA3-512 |
| Database | LMDB |
| Consensus | DPoS + Quadratic Voting |
| Block Time | 2-4 seconds |
| Target TPS | 500-1,500 |
| Finality | Deterministic (<5 seconds) |
| Account Model | Account-based (not UTXO) |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                              Chain                                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐ │
│  │ ChainDb  │  │ChainState│  │ Mempool  │  │       Miner          │ │
│  │  (LMDB)  │  │ (World)  │  │(Pending) │  │(Block Production)    │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────────┘ │
│        │             │             │                   │             │
│        └─────────────┴─────────────┴───────────────────┘             │
│                              │                                       │
│  ┌───────────────────────────┴───────────────────────────────────┐  │
│  │                    BroadcastManager (P2P)                      │  │
│  └────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
            ┌──────────────┐               ┌──────────────┐
            │  Celestia DA │               │  Coordinator │
            │  (Ordering)  │               │  (Scheduler) │
            └──────────────┘               └──────────────┘
```

### Component Overview

| Component | Description |
|-----------|-------------|
| **ChainDb** | LMDB persistence layer for blocks, state, and metadata |
| **ChainState** | World state including balances, validators, delegations, governance |
| **Mempool** | Pending transaction pool with validation |
| **Miner** | Block production with stake-weighted proposer selection |
| **BroadcastManager** | P2P block and transaction propagation |

## Modules

| Module | Description | Reference |
|--------|-------------|-----------|
| `types` | Core types: Address, Hash, constants | Core |
| `crypto` | Ed25519 signatures, SHA3-512 hashing | Core |
| `state` | Chain state management, validators, delegation | 13.8 |
| `db` | LMDB persistence with atomic commits | 13.7.I |
| `tx` | Transaction types and validation | 13.7.E |
| `block` | Block structure, headers, signing | 13.7.D |
| `mempool` | Transaction pool management | Core |
| `miner` | Block production, proposer selection | 13.7.D |
| `rpc` | JSON-RPC endpoints | 13.7.N |
| `cli` | Command line interface | 13.9 |
| `qv` | Quadratic Voting (√stake formula) | 13.8.C/D |
| `proposer` | Stake-weighted proposer selection | 13.7.D |
| `tokenomics` | Fee distribution (70/20/10 split) | 13.8.E |
| `slashing` | Validator/node slashing penalties | 13.8.J |
| `epoch` | Epoch rotation (default: 120 blocks) | 13.7.L |
| `receipt` | Resource receipts from Coordinator | 13.10 |
| `sync` | P2P sync: headers, blocks, state replay | 13.11 |
| `celestia` | Celestia DA integration | 13.11.5 |
| `economic` | Deflation controller, treasury burn | 13.15 |
| `wallet` | Wallet management, encryption | 13.17 |

## Staking Requirements

| Role | Minimum Stake | Description |
|------|---------------|-------------|
| Validator | 50,000 NUSA | Governance & compliance, identity-published |
| Delegator | 100,000 NUSA | Delegate to validators, participate in QV |
| Full Node (Regular) | 500 NUSA | Storage & compute, home/small server |
| Full Node (Data Center) | 5,000 NUSA | High-capacity storage & compute |

## Fee Model

### Fee Split by Resource Class

| Resource Class | Node | Validator | Treasury |
|----------------|------|-----------|----------|
| Storage | 70% | 20% | 10% |
| Compute | 70% | 20% | 10% |
| Transfer | 0% | 100% | 0% |
| Governance | 0% | 100% | 0% |
| Stake | 0% | 100% | 0% |

### Gas Formula

```
GAS = (BASE_OP_COST + (DATA_BYTES × PER_BYTE_COST) + (COMPUTE_CYCLES × PER_CYCLE_COST)) × NODE_MULTIPLIER / 100
```

**Base Operation Costs:**
- Transfer: 21,000
- Storage Operation: 50,000
- Compute Operation: 100,000
- Per Byte: 16
- Per Compute Cycle: 1
- Default Node Cost Index: 100 (1.0x multiplier)

### Anti-Self-Dealing

To prevent reward manipulation, if a node processes workload submitted by the same wallet address (or affiliated addresses), the node's 70% share is redirected to treasury.

## CLI Usage

### Basic Setup

```bash
# Set database path (default: ./chaindb)
export DSDN_DB_PATH="./chaindb"

# Or use --db-path flag
dsdn-chain --db-path ./chaindb <command>
```

### Chain Management

```bash
# Initialize genesis block with initial account
dsdn-chain init --genesis-account 0x... --amount 300000000

# Show chain status (height, tip hash)
dsdn-chain status

# Show balance (uses wallet address if --address not specified)
dsdn-chain balance
dsdn-chain balance --address 0x...
```

### Wallet Management

```bash
# Create new wallet (generates keypair, saves to wallet.dat)
dsdn-chain wallet create

# Import existing wallet from private key
dsdn-chain wallet import --privkey <hex>

# Show wallet status (address only)
dsdn-chain wallet status

# Sign a transaction with secret key
dsdn-chain wallet sign --tx <unsigned-tx-hex> --secret <secret-key-hex>

# Encrypt a file using wallet encryption
dsdn-chain wallet encrypt --file input.txt --output encrypted.bin

# Decrypt a file using wallet encryption
dsdn-chain wallet decrypt --file encrypted.bin --output output.txt
```

### Transactions

```bash
# Transfer NUSA
dsdn-chain submit-transfer --to 0x... --amount 100 --fee 10 --gas-limit 21000

# Storage operation payment
dsdn-chain submit-storage-op --to-node 0x... --amount 50 --operation-id "op123" --fee 10 --gas-limit 25000

# Compute execution payment
dsdn-chain submit-compute-exec --to-node 0x... --amount 30 --execution-id "exec456" --fee 10 --gas-limit 40000
```

### Staking & Delegation

```bash
# Register as validator (requires min 50,000 NUSA stake)
dsdn-chain submit-validator-reg --pubkey <hex> --min-stake 50000 --fee 10 --gas-limit 80000

# Stake to validator
dsdn-chain submit-stake --validator 0x... --amount 1000 --fee 10 --gas-limit 50000

# Stake with delegation bond (--bond flag)
dsdn-chain submit-stake --validator 0x... --amount 1000 --bond --fee 10 --gas-limit 50000

# Delegate stake shortcut (equivalent to submit-stake --bond)
dsdn-chain delegate --validator 0x... --amount 1000 --fee 10

# Delegator stake (min 100,000 NUSA, explicit delegator staking)
dsdn-chain submit-delegator-stake --validator 0x... --amount 100000 --fee 10 --gas-limit 50000

# Unstake (7-day delay applies)
dsdn-chain submit-unstake --validator 0x... --amount 500 --fee 10 --gas-limit 50000

# Withdraw delegator stake
dsdn-chain withdraw-delegator-stake --validator 0x... --amount 50000 --fee 10 --gas-limit 50000
```

### Query Commands

```bash
# List all validators with stake and voting power
dsdn-chain validators

# Show detailed validator info including delegations
dsdn-chain validator-info --address 0x...

# Show staking info for current wallet
dsdn-chain staking-info

# Show current epoch and network info
dsdn-chain epoch-info

# Show treasury, reward pool, and delegator pool balances
dsdn-chain pool-info
```

### Governance

```bash
# Create proposal
dsdn-chain governance propose \
  --type update-fee \
  --title "Reduce storage fee" \
  --description "Proposal to reduce storage fees by 10%" \
  --fee 10 --gas-limit 100000

# Vote on proposal (yes, no, abstain)
dsdn-chain governance vote --proposal 1 --vote yes --fee 10 --gas-limit 50000

# Finalize proposal after voting period
dsdn-chain governance finalize --proposal 1 --fee 10 --gas-limit 75000

# Foundation veto a proposal (Bootstrap Mode only)
dsdn-chain governance foundation-veto --proposal 1 --fee 10 --gas-limit 50000

# List active proposals
dsdn-chain governance list-active

# List all proposals (all statuses)
dsdn-chain governance list-all

# Show proposal details
dsdn-chain governance show --proposal 1

# Show my votes on all proposals
dsdn-chain governance my-votes

# Show current governance configuration
dsdn-chain governance config

# Preview proposal changes (READ-ONLY, does NOT execute)
dsdn-chain governance preview --proposal 1

# Check bootstrap mode status
dsdn-chain governance bootstrap-status

# View recent governance events
dsdn-chain governance events --count 20
```

**Proposal Types:**
- `update-fee` — Update fee parameters
- `update-gas` — Update gas parameters
- `update-node-cost` — Update node cost index
- `validator-onboard` — Onboard new validator
- `validator-offboard` — Offboard validator
- `compliance-remove` — Remove compliance pointer
- `emergency-pause` — Emergency system pause

### Resource Receipts

```bash
# Claim reward from Coordinator receipt
dsdn-chain submit-claim-reward --receipt-file receipt.json --fee 10 --gas-limit 30000

# Or use receipt subcommand
dsdn-chain receipt claim --file receipt.json --fee 10 --gas-limit 30000

# Check receipt status (claimed or not)
dsdn-chain receipt status --id 0x...

# View accumulated node earnings
dsdn-chain receipt earnings --address 0x...
```

### Service Node Gating

```bash
# Register a new service node on-chain
dsdn-chain service-node register \
  --node-id <ed25519-pubkey-hex> \
  --class storage \
  --tls-fingerprint <sha256-hex> \
  --fee 10 --gas-limit 80000

# Show detailed service node info (READ-ONLY)
dsdn-chain service-node info --address 0x...
dsdn-chain service-node info --address 0x... --json

# Show stake info for a service node (READ-ONLY)
dsdn-chain service-node stake --address 0x...
dsdn-chain service-node stake --address 0x... --json

# Show service node status (READ-ONLY)
dsdn-chain service-node status --address 0x...
dsdn-chain service-node status --address 0x... --json

# List all active service nodes (READ-ONLY)
dsdn-chain service-node list
dsdn-chain service-node list --json
```

**Node Classes:** `storage`, `compute`

### Economic Observability

```bash
# Show economic status (mode, replication factor, treasury, supply, burn rate)
dsdn-chain economic status

# Show deflation configuration and state
dsdn-chain economic deflation

# Show burn event history
dsdn-chain economic burn-history --count 20
```

### Slashing Observability

```bash
# Show node liveness status
dsdn-chain slashing node-status --address 0x...

# Show validator slash status
dsdn-chain slashing validator-status --address 0x...

# Show recent slashing events
dsdn-chain slashing events --count 10
```

### Sync Management

```bash
# Start sync to network tip
dsdn-chain sync start

# Stop ongoing sync process
dsdn-chain sync stop

# Show current sync status
dsdn-chain sync status

# Show sync progress with progress bar and ETA
dsdn-chain sync progress

# Reset sync state (clear metadata, restart from genesis)
dsdn-chain sync reset

# Fast sync from a snapshot
dsdn-chain sync fast --from-snapshot 10000
```

### Snapshots

```bash
# List all available snapshots
dsdn-chain snapshot list

# Create snapshot at current height
dsdn-chain snapshot create

# Show detailed snapshot info (height, timestamp, state_root)
dsdn-chain snapshot info --height 10000
```

### Storage Contracts

```bash
# List all contracts for an address
dsdn-chain storage list --address 0x...

# Show detailed contract info
dsdn-chain storage info --contract 0x...
```

### Data Availability (Celestia)

```bash
# Verify blob commitment
dsdn-chain da verify --blob <hex> --commitment <hex>
```

### Node Cost Index (Admin)

```bash
# Set node cost multiplier (basis 100 = 1.0x)
dsdn-chain node-cost set --address 0x... --multiplier 150

# Get current node cost index
dsdn-chain node-cost get --address 0x...

# List all node cost indexes
dsdn-chain node-cost list

# Remove (revert to default)
dsdn-chain node-cost remove --address 0x...
```

### Mining (Development)

```bash
# Mine a new block (proposer selected by stake-weight if validators exist)
dsdn-chain mine

# Mine with specific proposer address (fallback)
dsdn-chain mine --miner-addr 0x...
```

### Testing

```bash
# Run E2E integration tests
dsdn-chain test-e2e --module all --verbose

# Available modules: proposer, stake, qv, block, mempool, epoch, fullnode, all

# Run full integration test suite (13.19)
dsdn-chain test full
```

## Governance Modes

DSDN implements progressive governance that evolves with network maturity:

### Phase 0: Pre-Governance (Foundation Mode)
- No public governance or voting
- Static protocol parameters
- Foundation Key has limited operational authority
- All operations are transparent and auditable

### Phase 1: Bootstrap Mode
- Validators can propose and vote
- **All votes are non-binding (advisory only)**
- Foundation has veto/override power
- Slashing is limited to automatic mechanisms

### Phase 2: Transition Mode
- Proposals execute after delay period
- Quadratic Voting from community is counted
- Limited governance-based slashing with appeals
- Foundation role gradually reduced

### Phase 3: Full Governance
- No Foundation veto or override
- Full on-chain governance execution
- Validators + QV community decide all matters
- Complete decentralization achieved

## Slashing Rules

| Violation | Penalty | Cooldown |
|-----------|---------|----------|
| Liveness Failure (>12h) | 0.5% stake | None |
| Data Corruption (2x verified) | 5% stake | 14 days |
| Repeated Malicious Behavior | Force unbond | 30 days ban |

## Consensus-Critical Components

The following components are consensus-critical and require a hard fork to modify:

- Gas constants (`state/internal_gas.rs`)
- Fee split percentages (`tokenomics.rs`)
- State root hashing (`state/internal_state_root.rs`)
- Node cost index (`state/internal_node_cost.rs`)
- Receipt verification (`state/internal_receipt.rs`)
- Coordinator public key (`receipt.rs`)
- Claimed receipts (state_root position #25)
- Storage contracts (state_root position #35)
- Challenge period duration (`economic_constants::CHALLENGE_PERIOD_SECS`)
- Minimum challenger stake (`fraud_proof_handler::MIN_CHALLENGER_STAKE`)
- Pending challenges map (included in state_root)

## Receipt & Challenge Lifecycle (CH.6–CH.10)

### Receipt Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                     ClaimReward Transaction                          │
│                                                                      │
│  ReceiptV1 submitted via TxPayload::ClaimReward                     │
│  │                                                                   │
│  ├── verify_receipt_v1()                                            │
│  │   ├── Threshold signature check                                  │
│  │   ├── Node signature check                                      │
│  │   ├── Dedup check (receipt_dedup_tracker)                       │
│  │   └── Node registration check (service_node_index)              │
│  │                                                                   │
│  ├── anti_self_dealing_check()                                      │
│  │   └── If node == sender → redirect node_share to treasury       │
│  │                                                                   │
│  └── Route by receipt_type:                                         │
│      │                                                               │
│      ├── Storage ──▶ distribute immediately (70/20/10)              │
│      │   └── execute_reward_distribution(state, distribution, addr) │
│      │                                                               │
│      └── Compute ──▶ start_challenge_period()                       │
│          └── Hold reward in pending_challenges                      │
│              └── Wait for challenge period to expire                │
└──────────────────────────────────────────────────────────────────────┘
```

### Reward Math

```
Storage/Compute fee split (13.8.E + 13.9 Blueprint):

  reward_base = total reward amount
  node_share       = reward_base × 70 / 100
  validator_share  = reward_base × 20 / 100
  treasury_share   = reward_base - node_share - validator_share  (remainder)

Anti-self-dealing (node == sender):
  node_share       = 0
  validator_share  = reward_base × 20 / 100
  treasury_share   = reward_base - validator_share  (70% + 10%)

Transfer/Governance:
  validator_share  = 100%
  node_share       = 0%
  treasury_share   = 0%
```

### Challenge State Machine

```
                        ┌─────────┐
                        │ Pending │
                        └────┬────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
         (expired,      (fraud proof   (fraud proof
          no fraud)      submitted,     submitted,
              │          proven)        not proven)
              ▼              │              │
        ┌─────────┐         │              │
        │ Cleared │         │              ▼
        └────┬────┘         │        ┌────────────┐
             │              │        │ Challenged │
        distribute          │        └────────────┘
        reward              │              │
             │              │         (future CH.8+
        remove entry        │          resolution)
                            ▼
                      ┌──────────┐
                      │ Slashed  │
                      └──────────┘
                       (terminal)

Valid transitions:
  Pending → Cleared      (challenge period expired, no fraud proof)
  Pending → Challenged   (fraud proof submitted via mark_challenged)
  Challenged → Slashed   (fraud proven via mark_slashed)

Invalid transitions (no-op):
  Cleared → anything     (terminal)
  Slashed → anything     (terminal)
  Challenged → Cleared   (rejected by state machine)
  Pending → Slashed      (must go through Challenged first)
```

### Failure Modes

| Failure | Behavior | Recovery |
|---------|----------|----------|
| Receipt not in pending_challenges | `FraudProofError::ReceiptNotPending` | None needed (invalid input) |
| Challenge period expired | `FraudProofError::ChallengePeriodExpired` | Challenge proceeds to clear on next block |
| Insufficient challenger stake | `FraudProofError::InsufficientChallengerStake` | Challenger must stake more |
| Double challenge on same receipt | `FraudProofError::ChallengeNotPending` | First challenge stands |
| Node not in service_node_index | Challenge skipped, stays Pending | Retry on next block expiry cycle |
| Reward distribution overflow | Challenge stays, no partial credit | Degenerate case (u128 overflow) |
| Empty fraud proof data | `fraud_proven = false`, marked Challenged | Dispute via future mechanism |

### Idempotency Guarantee

`process_expired_challenges(state, time)` is idempotent:

1. Cleared entries are removed from `pending_challenges` after distribution.
   Second call finds nothing → empty result.
2. Terminal entries (Cleared, Slashed) are skipped.
   Calling again produces no additional state changes.
3. Challenged entries produce `PendingResolution` without mutation.
   Multiple calls return same result without side effects.

### Audit Checklist

```
[x] No panic in production code (zero panic!, unreachable!, unwrap, expect)
[x] No partial state update (mutations after validation boundary only)
[x] No double reward (cleared entries removed; idempotent)
[x] No double challenge (Pending status check rejects second submission)
[x] Deterministic (sorted iteration, no randomness, no IO)
[x] Overflow safe (saturating_add throughout)
[x] Thread safe (ChainState protected by RwLock; functions require &mut)
[x] Consensus-critical (pending_challenges included in state_root)
[x] Block pipeline consistent (miner + full node call at same position)
[x] Backward compatible (ResourceReceipt V0 still functional)
```

### Migration Strategy: ResourceReceipt (V0) → ReceiptV1 (V1)

```
Phase 1 (Current):
  - Both V0 and V1 receipts accepted by chain
  - V0 can convert to V1 via to_receipt_v1() (lossy, Storage only)
  - V1 is the canonical format for new receipts
  - node_class deprecated in V1

Phase 2 (Future):
  - V0 receipt acceptance deprecated
  - All nodes generate V1 receipts
  - to_receipt_v1() bridge unused

Phase 3 (Final):
  - V0 code paths removed
  - ResourceReceipt struct removed
  - Only ReceiptV1 remains
```

## Integration with DSDN Ecosystem

### Coordinator Integration

The chain receives `ResourceReceipt` from the Coordinator for workload claims:

```
ResourceReceipt {
    receipt_id: Hash,           // Unique ID (SHA3-512)
    node_address: Address,      // Service node
    node_class: NodeClass,      // Storage / Compute
    resource_type: ResourceType,
    measured_usage: MeasuredUsage,
    reward_base: u128,          // Reward amount
    anti_self_dealing_flag: bool,
    timestamp: u64,
    coordinator_signature: Vec<u8>,  // Ed25519
}
```

### Celestia DA Integration

Celestia provides Data Availability for control-plane state:
- Ordering and availability of metadata blobs
- State reconstruction from blob sequence
- No state storage (stateless ordering only)

**Control Plane Update Types:**
- `ReceiptBatch` — Batch of ResourceReceipts
- `ValidatorSetUpdate` — Validator set changes
- `ConfigUpdate` — Protocol parameter changes
- `Checkpoint` — State snapshot reference

## Minimal Operational Requirements

| Component | Minimum | Production Target |
|-----------|---------|-------------------|
| Validators | 1 (survivability) | 100-150 |
| Full Nodes | 1 (degraded mode) | 3+ nodes in 3+ zones |
| Replication Factor | 1 (no durability) | 3 (RF=3) |

**Note:** With fewer than 3 nodes in 3 zones, the system operates in degraded mode without durability guarantees.

## Building

```bash
# Build the crate
cargo rustsp build --release

# Run tests
cargo rustsp test

# Build documentation
cargo rustsp doc --open
```

## Dependencies

Key external dependencies:
- `lmdb` — Persistent key-value storage
- `ed25519-dalek` — Ed25519 signatures
- `sha3` — SHA3-512 hashing
- `bincode` — Binary serialization
- `parking_lot` — Synchronization primitives
- `clap` — CLI argument parsing
- `serde` — Serialization framework

## License

Proprietary. See LICENSE for details.

---

**DSDN Chain** — Building decentralized infrastructure for Indonesia 🇮🇩