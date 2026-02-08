# DSDN Agent CLI (14A)

Command-line interface for DSDN (Distributed Storage and Data Network).

## Overview

The DSDN Agent provides a comprehensive CLI for interacting with the DSDN network. It supports key management, data operations, state verification, and health monitoring - all with first-class DA (Data Availability) layer integration.

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

All node and chunk queries derive their data from DA events only - no RPC to nodes or coordinator required.

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

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DSDN_DA_ENDPOINT` | `http://127.0.0.1:26658` | DA layer endpoint |
| `DSDN_DA_NAMESPACE` | `dsdn` | DA namespace |
| `DSDN_COORDINATOR_ENDPOINT` | `http://127.0.0.1:8080` | Coordinator endpoint |

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
```

## License

Copyright BITEVA. All rights reserved.