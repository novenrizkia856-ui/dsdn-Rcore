# DSDN Agent CLI (14A–14C)

Command-line interface for DSDN (Distributed Storage and Data Network).

## Overview

The DSDN Agent provides a comprehensive CLI for interacting with the DSDN network. It supports key management, data operations, state verification, health monitoring, identity management, service node gating, and a full economic lifecycle — all with first-class DA (Data Availability) layer integration.

## Installation

```bash
cargo rustsp build --release -p dsdn-agent
```

## Commands

### Key Management

| Command | Description |
|---------|-------------|
| `gen-key` | Generate encryption key (32 bytes), optionally split into SSS shares |
| `recover-key` | Recover key from SSS shares |

```bash
# Generate a simple key
agent gen-key

# Generate key and split into 5 shares with threshold 3
agent gen-key -n 5 -k 3 --out-dir ./shares

# Recover key from shares
agent recover-key share1.bin share2.bin share3.bin
```

### Data Operations

| Command | Description |
|---------|-------------|
| `upload` | Upload file to network node |
| `get` | Download file from network node |
| `decrypt-file` | Decrypt local encrypted file |

```bash
# Upload file (plain)
agent upload 127.0.0.1:50051 myfile.txt

# Upload with encryption and DA tracking
agent upload 127.0.0.1:50051 myfile.txt --encrypt --track --rf 3

# Download file
agent get 127.0.0.1:50051 <hash>

# Download with DA verification (multi-source)
agent get 127.0.0.1:50051 <hash> --verify --out myfile.txt

# Decrypt local file
agent decrypt-file encrypted.bin output.txt <key_base64>
```

### DA Operations

| Command | Description |
|---------|-------------|
| `da status` | Check DA layer connection status and current height |

```bash
# Check DA status
agent da status

# Check DA status (JSON output)
agent da status --json
```

### Verification

| Command | Description |
|---------|-------------|
| `verify state` | Verify state consistency against DA-derived state |
| `verify consistency` | Check node consistency with DA state |

```bash
# Verify coordinator state
agent verify state --target coordinator

# Verify node consistency
agent verify consistency --node 127.0.0.1:50051
```

### Node/Chunk Info

All node and chunk queries derive their data from DA events only — no RPC to nodes or coordinator required.

| Command | Description |
|---------|-------------|
| `node status` | Show node status from DA events |
| `node list` | List all registered nodes from DA events |
| `node chunks` | Show chunks assigned to a node from DA events |
| `chunk info` | Show chunk info from DA events |
| `chunk replicas` | Show chunk replicas from DA events |
| `chunk history` | Show chunk event history from DA events |

```bash
# Node commands
agent node list
agent node status <node_id>
agent node chunks <node_id>

# Chunk commands
agent chunk info <hash>
agent chunk replicas <hash>
agent chunk history <hash>
```

### Identity Commands (14B)

Manage the cryptographic identity of a DSDN service node, including Ed25519 keypair generation, operator address binding, and identity export.

| Command | Description |
|---------|-------------|
| `identity generate` | Generate a new node identity (persistent or ephemeral) |
| `identity show` | Display identity details (node ID, operator address) |
| `identity export` | Export identity in hex, base64, or JSON format |

```bash
# Generate persistent identity to a directory
agent identity generate --out-dir ./my-identity

# Generate with operator address override
agent identity generate --out-dir ./my-identity --operator aabbccddeeff00112233aabbccddeeff00112233

# Generate ephemeral identity (printed to stdout, not saved)
agent identity generate --ephemeral

# Show identity details
agent identity show --dir ./my-identity

# Show identity details (JSON)
agent identity show --dir ./my-identity --json

# Export identity in hex format (WARNING: exposes secret key)
agent identity export --dir ./my-identity --format hex

# Export identity in JSON format
agent identity export --dir ./my-identity --format json
```

**Arguments:**

| Flag | Description | Required |
|------|-------------|----------|
| `--out-dir <path>` | Directory for persistent identity storage | Yes (for persistent) |
| `--ephemeral` | Generate ephemeral identity (not saved to disk) | No |
| `--operator <hex>` | Override operator address (40 hex chars, no 0x) | No |
| `--dir <path>` | Identity directory for show/export | Yes |
| `--json` | Output in JSON format (show only) | No |
| `--format <fmt>` | Export format: `hex`, `base64`, or `json` | Yes (export) |

### Gating Commands (14B)

Service node gating operations: stake verification, on-chain registration, status queries, slashing inspection, and full diagnosis.

| Command | Description |
|---------|-------------|
| `gating stake-check` | Check stake status for a service node |
| `gating register` | Register a service node on-chain |
| `gating status` | Query full gating status of a service node |
| `gating slashing-status` | Query slashing and cooldown status |
| `gating node-class` | Query node class and stake requirements |
| `gating list-active` | List all active service nodes sorted by stake |
| `gating quarantine-status` | Query quarantine details and recovery eligibility |
| `gating ban-status` | Query ban details and cooldown status |
| `gating diagnose` | Full gating diagnosis report (5 checks) |

```bash
# Check stake status
agent gating stake-check --address aaaa...aaaa

# Check stake status (JSON)
agent gating stake-check --address aaaa...aaaa --json

# Register service node on-chain
agent gating register \
  --identity-dir ./my-identity \
  --class storage \
  --chain-rpc https://mainnet.dsdn.io:8545 \
  --keyfile ./wallet.key

# Query full node status
agent gating status --address aaaa...aaaa

# Query slashing status
agent gating slashing-status --address aaaa...aaaa

# Query node class and stake requirements
agent gating node-class --address aaaa...aaaa

# List all active nodes
agent gating list-active

# List active nodes (JSON)
agent gating list-active --json

# Query quarantine status
agent gating quarantine-status --address aaaa...aaaa

# Query ban status
agent gating ban-status --address aaaa...aaaa

# Full gating diagnosis (chain-only)
agent gating diagnose --address aaaa...aaaa

# Full gating diagnosis with identity verification
agent gating diagnose \
  --address aaaa...aaaa \
  --identity-dir ./my-identity

# Full gating diagnosis (JSON)
agent gating diagnose --address aaaa...aaaa --json
```

**Common Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--address <hex>` | Operator address (40 hex chars, no 0x prefix) | Yes (most commands) |
| `--chain-rpc <url>` | Chain RPC endpoint URL | No (uses env/default) |
| `--json` | Output in JSON format | No |
| `--identity-dir <path>` | Path to identity directory | Yes (register), Optional (diagnose) |
| `--class <type>` | Node class: `storage` or `compute` | Yes (register) |
| `--keyfile <path>` | Path to wallet secret key file (64 hex chars) | Yes (register) |

**Diagnose Checks:**

The `gating diagnose` command runs 5 checks:

| Check | Description | Can Skip? |
|-------|-------------|-----------|
| Stake | Current stake meets minimum for class | No |
| Class | Node class is valid (Storage/Compute) | No |
| Identity | Local node ID matches chain record | Yes (no --identity-dir) |
| TLS | Local TLS fingerprint matches chain record | Yes (no fingerprint) |
| Cooldown | No active slashing cooldown | No |

Decision: APPROVED if all non-skipped checks pass, REJECTED if any check fails.

### Economic Commands (14C)

Full economic lifecycle management for service receipts — from workload dispatch through execution monitoring, proof building, receipt submission, and reward claiming.

#### Receipt Status Tracking (14C.C.16)

Track the lifecycle state of service receipts through a 9-state machine:

```text
Dispatched → Executing → ProofBuilt → Submitted → Pending → Finalized
     │            │           │            │          │
     └→Failed     └→Failed    └→Failed     ├→Rejected ├→Challenged → Finalized
                                           └→Failed              └→Rejected
```

| Command | Description |
|---------|-------------|
| `economic status <receipt_hash>` | Show receipt lifecycle status |
| `economic list` | List all tracked receipts (sorted by receipt_hash) |
| `economic summary` | Show aggregate summary by state |

```bash
# Show status of a specific receipt
agent economic status abc123def

# List all tracked receipts
agent economic list

# Show aggregate summary
agent economic summary
```

#### Workload Dispatch + Execution Monitoring (14C.C.18)

Dispatch workloads to service nodes and monitor execution status with retry and timeout enforcement.

| Command | Description |
|---------|-------------|
| `economic dispatch --type <type> --node <addr> <file>` | Dispatch a workload to a service node |
| `economic monitor <workload_id>` | Monitor execution status of a dispatched workload |

```bash
# Dispatch a storage workload
agent economic dispatch --type storage --node 127.0.0.1:50051 payload.bin

# Dispatch a compute workload
agent economic dispatch --type compute --node 10.0.0.5:50051 model.bin

# Monitor execution status
agent economic monitor wk-abc123
```

**Dispatch Arguments:**

| Flag | Description | Required |
|------|-------------|----------|
| `--type <type>` | Workload type: `storage` or `compute` | Yes |
| `--node <addr>` | Target node address (host:port) | Yes |
| `<file>` | File containing workload data | Yes |

**Execution Status Values:**

| Status | Description |
|--------|-------------|
| `Running` | Execution in progress (includes progress 0.0–1.0) |
| `Completed` | Execution finished (includes output_hash, duration_ms) |
| `Failed` | Execution failed (includes error message) |

#### Receipt Submission + Chain Claim (14C.C.19)

Submit receipt claims to the chain and poll claim status with double-claim protection.

| Command | Description |
|---------|-------------|
| `economic claim <receipt_hash>` | Submit a receipt claim to the chain |
| `economic claim-status <receipt_hash>` | Poll claim status on-chain |

```bash
# Submit a claim for a receipt
agent economic claim abc123def456

# Check claim status
agent economic claim-status abc123def456
```

**Claim Results:**

| Result | Description |
|--------|-------------|
| `ImmediateReward` | Reward granted immediately (amount + tx_hash) |
| `ChallengePeriodStarted` | Challenge period opened (challenge_id + expires_at) |
| `Rejected` | Claim rejected by chain (reason) |

**Claim Status Values:**

| Status | Description |
|--------|-------------|
| `Pending` | Claim is pending processing |
| `InChallengePeriod` | Claim is in challenge period (expires_at) |
| `Finalized` | Claim finalized with reward |
| `Rejected` | Claim was rejected (reason) |

**Error Classification:**

| Error | Description |
|-------|-------------|
| `AlreadyClaimed` | Receipt has already been claimed on-chain |
| `IngressUnavailable` | Ingress endpoint is not reachable |
| `InvalidReceipt` | Receipt data is empty or malformed |
| `NetworkError` | Network-level failure (retryable) |

#### Full Lifecycle Orchestration (14C.C.20)

Run the complete economic flow as a single command — from workload dispatch through reward claiming.

| Command | Description |
|---------|-------------|
| `economic run --type <type> [--auto-claim] [--node <addr>] <file>` | Run full economic lifecycle |

```bash
# Run full flow (no auto-claim)
agent economic run --type storage payload.bin

# Run full flow with auto-claim enabled
agent economic run --type compute --auto-claim model.bin

# Run with custom node address
agent economic run --type storage --auto-claim --node 10.0.0.5:50051 payload.bin
```

**Run Arguments:**

| Flag | Description | Default |
|------|-------------|---------|
| `--type <type>` | Workload type: `storage` or `compute` | Required |
| `--auto-claim` | Automatically submit claim after receipt | `false` |
| `--node <addr>` | Target node address (host:port) | `127.0.0.1:50051` |
| `<file>` | File containing workload data | Required |

**Flow Steps (strict order, no skipping):**

```text
Step 1: Dispatch        → Send workload to service node
Step 2: Monitor         → Poll execution until Completed or Failed
Step 3: Build Proof     → Generate proof from execution output
Step 4: Submit Receipt  → Submit proof receipt to coordinator
Step 5: Claim (opt)     → Submit reward claim + poll until terminal
```

**Flow Result:**

The `economic run` command outputs:

| Field | Description |
|-------|-------------|
| `Workload ID` | Identifier assigned by the coordinator |
| `Receipt Hash` | Hash of the submitted receipt |
| `Claim` | Claim result (if `--auto-claim`) |
| `Duration` | Total wall-clock time (milliseconds) |
| `Steps` | Ordered list of completed steps |

**Error Recovery:**

Each step uses exponential backoff retry. If a step fails after exhausting retries, the flow stops immediately, the state tracker is updated to `Failed`, and the specific error is reported.

### Maintenance

| Command | Description |
|---------|-------------|
| `rebuild` | Rebuild state from DA events |
| `health all` | Check health of all components |
| `health da` | Check DA layer health only |
| `health coordinator` | Check coordinator health only |
| `health nodes` | Check all nodes health |

```bash
# Rebuild state from DA
agent rebuild --target node --from 1 --to 1000
agent rebuild --target coordinator --output state.json

# Health checks
agent health all
agent health da
agent health coordinator
agent health nodes
```

## Retry Logic (14C.C.17)

All network operations in the economic pipeline use configurable retry with exponential backoff:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_retries` | 3 | Maximum number of attempts |
| `initial_delay_ms` | 500 | Delay before first retry (ms) |
| `max_delay_ms` | 10,000 | Maximum delay cap (ms) |
| `backoff_multiplier` | 2.0 | Exponential multiplier per attempt |
| `jitter` | true | Deterministic jitter to avoid thundering herd |

**Delay formula:** `delay = min(initial_delay_ms × multiplier^(attempt−1), max_delay_ms) + jitter`

**Error classification:**
- **Retryable:** network errors, connection refused, timeout, DNS failure
- **Non-retryable:** validation errors, invalid response, already claimed — stop immediately

## Validator Reward System (14C.C.15)

Comprehensive documentation and integration tests for the validator reward pipeline:

- **20% validator share** of service receipt fees
- **Overflow-safe** total_earned computation (u128)
- **Deterministic** sorting of reward summaries
- **Full pipeline testing:** receipt finalization → reward calculation → distribution → query
- **Trust model:** validators trust the chain for receipt finalization; rewards are computed locally

### Architecture

```text
Chain (DA)          Agent               Reward Pool
   │                  │                     │
   ├─FinReceipt──────►├─process_receipts───►├─calculate_share()
   │                  │                     ├─add_reward()
   │                  ├─query_summary()◄────├─get_summary()
   │                  ├─query_history()◄────├─get_history()
```

## Economic Flow State Machine

The receipt status tracker enforces a validated state machine:

```text
Dispatched → Executing → ProofBuilt → Submitted → Pending → Finalized
     │            │           │            │          │
     └→Failed     └→Failed    └→Failed     ├→Rejected ├→Challenged → Finalized
                                           └→Failed              └→Rejected
```

**Invariants:**
1. State transitions are validated; invalid transitions return `TrackerError::InvalidTransition`
2. Terminal states (`Finalized`, `Rejected`, `Failed`) block further transitions
3. `list_pending()` and `list_by_status()` return results sorted by `receipt_hash` (deterministic)
4. `summary()` is computed from counts, independent of `HashMap` iteration order

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DSDN_DA_ENDPOINT` | `http://127.0.0.1:26658` | DA layer endpoint |
| `DSDN_DA_NAMESPACE` | `dsdn` | DA namespace |
| `DSDN_COORDINATOR_ENDPOINT` | `http://127.0.0.1:45831` | Coordinator endpoint (dispatch, monitor, receipt submission) |
| `DSDN_INGRESS_ENDPOINT` | `http://127.0.0.1:45832` | Ingress endpoint (claim submission, claim status polling) |
| `DSDN_CHAIN_RPC` | `http://127.0.0.1:8545` | Chain RPC endpoint for gating commands |

**Chain RPC Resolution Order (gating commands):**

1. `--chain-rpc <url>` CLI argument (highest priority)
2. `DSDN_CHAIN_RPC` environment variable
3. Default: `http://127.0.0.1:8545`

Note: `gating register` requires `--chain-rpc` explicitly; there is no fallback.

## DA Integration

The agent can query state directly from the DA (Data Availability) layer. This architecture provides:

1. **Decoupled reads**: Read operations (node/chunk queries) don't require Coordinator
2. **DA as source of truth**: All state is derived from DA events
3. **Verification**: Upload/download operations can verify against DA commitments
4. **Rebuild capability**: Full state can be reconstructed from DA events

### DA Events

The agent understands the following DA event types:

- `NodeRegistered`: Node joins the network
- `NodeUnregistered`: Node leaves the network
- `ChunkDeclared`: New chunk is declared
- `ReplicaAdded`: Replica assigned to node
- `ReplicaRemoved`: Replica removed from node
- `DeleteRequested`: Chunk deletion requested

## Examples

### Example 1: Generate Identity & Register Node

```bash
# Create identity directory and generate persistent identity
mkdir -p ./my-node-identity
agent identity generate --out-dir ./my-node-identity

# Verify identity was created
agent identity show --dir ./my-node-identity

# Register as a storage node on mainnet
agent gating register \
  --identity-dir ./my-node-identity \
  --class storage \
  --chain-rpc https://mainnet.dsdn.io:8545 \
  --keyfile ./wallet.key
```

### Example 2: Diagnose Node Gating

```bash
# Quick diagnosis (chain data only)
agent gating diagnose \
  --address aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

# Full diagnosis with identity and TLS verification
agent gating diagnose \
  --address aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --identity-dir ./my-node-identity \
  --json
```

### Example 3: Run Full Economic Flow

```bash
# Dispatch a storage workload and auto-claim the reward
agent economic run \
  --type storage \
  --auto-claim \
  --node 10.0.0.5:50051 \
  payload.bin

# Output:
# Flow completed:
#   Workload ID:  wk-abc123
#   Receipt Hash: receipt-ohash
#   Claim:        Immediate reward 5000 (tx: 0xabc...)
#   Duration:     4230ms
#   Steps:        dispatch → monitor → proof → submit_receipt → claim
```

### Example 4: Step-by-Step Economic Flow

```bash
# Step 1: Dispatch workload
agent economic dispatch --type compute --node 10.0.0.5:50051 model.bin

# Step 2: Monitor execution
agent economic monitor wk-abc123

# Step 3: Check receipt status
agent economic status receipt-ohash

# Step 4: Submit claim
agent economic claim receipt-ohash

# Step 5: Poll claim status
agent economic claim-status receipt-ohash

# Check overall summary
agent economic summary
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success / Healthy |
| 1 | Error / Unhealthy |

For health commands, exit code 1 indicates one or more components are unhealthy or degraded.

## Output Formats

Most commands support `--json` flag for JSON output, suitable for scripting and automation.

```bash
agent node list --json
agent health all --json
agent da status --json
agent gating status --address aaaa...aaaa --json
agent gating diagnose --address aaaa...aaaa --json
```

## Development Stages

| Stage | Module | Description |
|-------|--------|-------------|
| 14A | Core CLI | Key management, data ops, DA, verification, node/chunk info, health |
| 14B.51–52 | Identity | Ed25519 keypair generation, operator binding, export |
| 14B.53–59 | Gating | Stake check, registration, status, slashing, diagnosis |
| 14C.C.13 | Reward Query | Read-only reward query interface with overflow-safe computation |
| 14C.C.14 | Chain Integration | Async reward pool reader, 20% validator share, atomic state updates |
| 14C.C.15 | Reward Tests + Docs | 20 integration tests, comprehensive architecture documentation |
| 14C.C.16 | Economic Flow Types | 9-state lifecycle enum, validated transitions, CLI (status/list/summary) |
| 14C.C.17 | Retry Logic | Exponential backoff, deterministic jitter, error classification |
| 14C.C.18 | Workload Dispatch | Dispatch + monitor with retry integration, timeout, response validation |
| 14C.C.19 | Receipt Claim | Claim submission, polling, double-claim protection, ingress handling |
| 14C.C.20 | Orchestration | Full lifecycle: dispatch → monitor → proof → submit → claim |

## License

MIT LICENSE