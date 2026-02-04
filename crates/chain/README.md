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

### Wallet Management

```bash
# Create new wallet
dsdn-chain wallet create

# Import existing wallet
dsdn-chain wallet import --privkey <hex>

# Show wallet status
dsdn-chain wallet status

# Encrypt a file
dsdn-chain wallet encrypt --file input.txt --output encrypted.bin

# Decrypt a file
dsdn-chain wallet decrypt --file encrypted.bin --output output.txt
```

### Chain Status & Queries

```bash
# Show chain status (height, tip hash)
dsdn-chain status

# Show balance
dsdn-chain balance
dsdn-chain balance --address 0x...

# List validators
dsdn-chain validators

# Show validator details
dsdn-chain validator-info --address 0x...

# Show staking info for current wallet
dsdn-chain staking-info

# Show epoch and network info
dsdn-chain epoch-info

# Show treasury and pool balances
dsdn-chain pool-info
```

### Transactions

```bash
# Transfer NUSA
dsdn-chain submit-transfer --to 0x... --amount 100 --fee 10

# Storage operation payment
dsdn-chain submit-storage-op --to-node 0x... --amount 50 --operation-id "op123"

# Compute execution payment
dsdn-chain submit-compute-exec --to-node 0x... --amount 30 --execution-id "exec456"
```

### Staking & Delegation

```bash
# Register as validator (requires 50,000 NUSA)
dsdn-chain submit-validator-reg --pubkey <hex> --min-stake 50000

# Stake to validator
dsdn-chain submit-stake --validator 0x... --amount 1000

# Delegate to validator (with --bond flag)
dsdn-chain submit-stake --validator 0x... --amount 1000 --bond

# Delegator stake (min 100,000 NUSA)
dsdn-chain submit-delegator-stake --validator 0x... --amount 100000

# Unstake (7-day delay applies)
dsdn-chain submit-unstake --validator 0x... --amount 500

# Withdraw delegator stake
dsdn-chain withdraw-delegator-stake --validator 0x... --amount 50000
```

### Governance

```bash
# Create proposal
dsdn-chain governance propose \
  --type update-fee \
  --title "Reduce storage fee" \
  --description "Proposal to reduce storage fees by 10%"

# Vote on proposal
dsdn-chain governance vote --proposal 1 --vote yes

# Finalize proposal after voting period
dsdn-chain governance finalize --proposal 1

# List active proposals
dsdn-chain governance list-active

# List all proposals
dsdn-chain governance list-all

# Show proposal details
dsdn-chain governance show --proposal 1

# Show my votes
dsdn-chain governance my-votes

# Preview proposal changes (READ-ONLY)
dsdn-chain governance preview --proposal 1

# Check bootstrap mode status
dsdn-chain governance bootstrap-status

# View governance events
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
dsdn-chain submit-claim-reward --receipt-file receipt.json

# Or use receipt subcommand
dsdn-chain receipt claim --file receipt.json

# Check receipt status
dsdn-chain receipt status --id 0x...

# View node earnings
dsdn-chain receipt earnings --address 0x...
```

### Economic Observability

```bash
# Show economic status (mode, treasury, supply, burn rate)
dsdn-chain economic status

# Show deflation configuration
dsdn-chain economic deflation

# Show burn history
dsdn-chain economic burn-history --count 20
```

### Slashing Observability

```bash
# Show node liveness status
dsdn-chain slashing node-status --address 0x...

# Show validator slash status
dsdn-chain slashing validator-status --address 0x...

# Show slashing events
dsdn-chain slashing events --count 10
```

### Sync Management

```bash
# Start sync to network tip
dsdn-chain sync start

# Stop sync
dsdn-chain sync stop

# Show sync status
dsdn-chain sync status

# Show sync progress with ETA
dsdn-chain sync progress

# Reset sync state
dsdn-chain sync reset

# Fast sync from snapshot
dsdn-chain sync fast --from-snapshot 10000
```

### Snapshots

```bash
# List available snapshots
dsdn-chain snapshot list

# Create snapshot at current height
dsdn-chain snapshot create

# Show snapshot details
dsdn-chain snapshot info --height 10000
```

### Storage Contracts

```bash
# List contracts for address
dsdn-chain storage list --address 0x...

# Show contract details
dsdn-chain storage info --contract 0x...
```

### Data Availability (Celestia)

```bash
# Verify blob commitment
dsdn-chain da verify --blob <hex> --commitment <hex>
```

### Node Cost Index (Admin)

```bash
# Set node cost multiplier
dsdn-chain node-cost set --address 0x... --multiplier 150

# Get node cost index
dsdn-chain node-cost get --address 0x...

# List all node cost indexes
dsdn-chain node-cost list

# Remove (revert to default)
dsdn-chain node-cost remove --address 0x...
```

### Mining (Development)

```bash
# Mine a new block
dsdn-chain mine

# Mine with specific proposer (fallback)
dsdn-chain mine --miner-addr 0x...
```

### Testing

```bash
# Run E2E integration tests
dsdn-chain test-e2e --module all --verbose

# Run full integration test suite
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
