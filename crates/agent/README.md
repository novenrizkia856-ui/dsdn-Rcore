# DSDN Agent CLI (14A–14B)

Command-line interface for DSDN (Distributed Storage and Data Network).

## Overview

The DSDN Agent provides a comprehensive CLI for interacting with the DSDN network. It supports key management, data operations, state verification, health monitoring, identity management, and service node gating — all with first-class DA (Data Availability) layer integration.

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

# Generate persistent identity with operator address override
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
agent gating stake-check --address aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

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

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DSDN_DA_ENDPOINT` | `http://127.0.0.1:26658` | DA layer endpoint |
| `DSDN_DA_NAMESPACE` | `dsdn` | DA namespace |
| `DSDN_COORDINATOR_ENDPOINT` | `http://127.0.0.1:8080` | Coordinator endpoint |
| `DSDN_CHAIN_RPC` | `http://127.0.0.1:8545` | Chain RPC endpoint for gating commands |

**Chain RPC Resolution Order (gating commands):**

1. `--chain-rpc <url>` CLI argument (highest priority)
2. `DSDN_CHAIN_RPC` environment variable
3. Default: `http://127.0.0.1:8545`

Note: `gating register` requires `--chain-rpc` explicitly; there is no fallback.

## Examples

### Example 1: Generate Identity

```bash
# Create identity directory and generate persistent identity
mkdir -p ./my-node-identity
agent identity generate --out-dir ./my-node-identity

# Verify identity was created
agent identity show --dir ./my-node-identity
```

### Example 2: Register Service Node

```bash
# Ensure identity exists
agent identity show --dir ./my-node-identity

# Register as a storage node on mainnet
agent gating register \
  --identity-dir ./my-node-identity \
  --class storage \
  --chain-rpc https://mainnet.dsdn.io:8545 \
  --keyfile ./wallet.key
```

### Example 3: Diagnose Node Gating

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

## License

Copyright BITEVA. All rights reserved.