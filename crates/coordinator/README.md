# DSDN Coordinator Crate

The Coordinator is the central orchestration component of DSDN (Decentralized Storage and Data Network). It manages node registry, data placement, workload scheduling, and integration with the Data Availability layer (Celestia).

## Table of Contents

- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Configuration](#configuration)
- [HTTP API Reference](#http-api-reference)
- [Components](#components)
- [Key Invariants](#key-invariants)
- [Module Structure](#module-structure)
- [Testing](#testing)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              COORDINATOR                                      │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                           HTTP Server (Axum)                           │ │
│  │  /register  /nodes  /schedule  /health  /da/*  /fallback/*  /system/* │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                      │                                       │
│                                      ▼                                       │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐         │
│  │   Coordinator   │    │    DARouter     │    │  Reconciliation │         │
│  │  (Node Registry │◀──▶│ (DA Operations) │◀──▶│     Engine      │         │
│  │   & Scheduler)  │    │                 │    │                 │         │
│  └─────────────────┘    └────────┬────────┘    └─────────────────┘         │
│                                  │                                          │
│                    ┌─────────────┼─────────────┐                           │
│                    ▼             ▼             ▼                           │
│              ┌──────────┐ ┌──────────┐ ┌──────────┐                        │
│              │ Primary  │ │Secondary │ │Emergency │                        │
│              │(Celestia)│ │(QuorumDA)│ │  (Mock)  │                        │
│              └──────────┘ └──────────┘ └──────────┘                        │
│                                                                              │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐         │
│  │   DAConsumer    │───▶│  StateMachine   │───▶│ DADerivedState  │         │
│  │ (Event Ingest)  │    │ (Event Apply)   │    │ (Authoritative) │         │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘         │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### DA Fallback System

```
┌───────────────────────────────────────────────────────────────────────────┐
│                         DA STATUS TRANSITIONS                             │
│                                                                           │
│   ┌─────────┐                                                             │
│   │ Healthy │◀──────────────────────────────────────────────────┐        │
│   │(Primary)│                                                    │        │
│   └────┬────┘                                                    │        │
│        │ health check fails                                      │        │
│        ▼                                                         │        │
│   ┌─────────┐                                                    │        │
│   │ Warning │ (primary_failures < failure_threshold)             │        │
│   └────┬────┘                                                    │        │
│        │ consecutive failures >= threshold                       │        │
│        ▼                                                         │        │
│   ┌─────────┐                                                    │        │
│   │Degraded │ (using secondary/QuorumDA)                         │        │
│   │(Fallback)│                                                   │        │
│   └────┬────┘                                                    │        │
│        │ secondary also fails                                    │        │
│        ▼                                                    Reconcile     │
│   ┌─────────┐                                               completes     │
│   │Emergency│ (using emergency DA)                               │        │
│   └────┬────┘                                                    │        │
│        │ primary health checks start succeeding                  │        │
│        ▼                                                         │        │
│   ┌──────────┐                                                   │        │
│   │Recovering│ (primary healthy, reconciling pending blobs)──────┘        │
│   └──────────┘                                                            │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Development Mode (MockDA)

```bash
# Start coordinator with mock DA — no Celestia node required
dsdn-coordinator serve --mock-da

# Coordinator listens on http://127.0.0.1:45831
```

### Production Mode (Celestia)

```bash
dsdn-coordinator serve \
    --da-rpc-url http://localhost:26658 \
    --da-namespace 0000000000000000000000000000000000000000000000000000000000 \
    --da-auth-token <TOKEN> \
    --da-network mainnet
```

### Quick Test

```bash
# Register a node
dsdn-coordinator node register --id node-1 --zone us-east --addr 10.0.0.1:50051

# List all nodes
dsdn-coordinator node list

# Register an object
dsdn-coordinator object register --hash abc123def456 --size 1048576

# Get object info
dsdn-coordinator object get abc123def456

# Health check
dsdn-coordinator health

# Readiness check
dsdn-coordinator ready
```

> **Note:** Management subcommands (`node`, `object`, `replica`, `health`, etc.)
> connect to a running coordinator via HTTP. Use `--coordinator-url` to target a
> different instance (default: `http://127.0.0.1:45831`).

---

## CLI Reference

### Global Options

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--coordinator-url` | `DSDN_COORDINATOR_URL` | `http://127.0.0.1:45831` | URL of the running coordinator (for management commands) |

### `serve` — Start the Coordinator Server

```bash
dsdn-coordinator serve [OPTIONS]
```

All flags accept environment variable fallbacks. CLI flags take precedence.

#### Primary DA

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--da-rpc-url` | `DA_RPC_URL` | *(required)* | Celestia light node RPC endpoint |
| `--da-namespace` | `DA_NAMESPACE` | *(required)* | 58-character hex namespace |
| `--da-auth-token` | `DA_AUTH_TOKEN` | — | Authentication token (required for mainnet) |
| `--da-network` | `DA_NETWORK` | `mainnet` | Network: `mainnet`, `mocha`, `local` |
| `--da-timeout-ms` | `DA_TIMEOUT_MS` | `30000` | Operation timeout in ms |
| `--mock-da` | `USE_MOCK_DA` | `false` | Use MockDA for development |

> `--da-rpc-url` and `--da-namespace` are not required when `--mock-da` is set.

#### HTTP Server

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--host` | `COORDINATOR_HOST` | `127.0.0.1` | Server bind address |
| `--port` | `COORDINATOR_PORT` | `45831` | Server bind port |

#### Fallback DA

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--enable-fallback` | `ENABLE_FALLBACK` | `false` | Enable fallback DA system |
| `--fallback-da-type` | `FALLBACK_DA_TYPE` | `none` | Type: `none`, `quorum`, `emergency` |
| `--quorum-validators` | `QUORUM_VALIDATORS` | — | Comma-separated validator addresses |
| `--quorum-threshold` | `QUORUM_THRESHOLD` | `67` | Quorum percentage (1–100) |
| `--emergency-da-url` | `EMERGENCY_DA_URL` | — | Emergency DA endpoint URL |

#### Reconciliation

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--reconcile-batch-size` | `RECONCILE_BATCH_SIZE` | `10` | Blobs per reconciliation batch |
| `--reconcile-max-retries` | `RECONCILE_MAX_RETRIES` | `3` | Max retry attempts per blob |
| `--reconcile-retry-delay-ms` | `RECONCILE_RETRY_DELAY_MS` | `1000` | Delay between retries in ms |
| `--reconcile-parallel` | `RECONCILE_PARALLEL` | `false` | Enable parallel reconciliation |

#### Environment File

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--env-file` | `DSDN_ENV_FILE` | *(auto-detect)* | Path to `.env` file for env var fallback |

Auto-detection order: `.env.mainnet` → `.env` → none.

#### Examples

```bash
# Minimal development
dsdn-coordinator serve --mock-da

# Production mainnet
dsdn-coordinator serve \
    --da-rpc-url http://localhost:26658 \
    --da-namespace 0000000000000000000000000000000000000000000000000000000000 \
    --da-auth-token eyJhbG... \
    --da-network mainnet \
    --host 0.0.0.0 --port 45831

# Production with QuorumDA fallback
dsdn-coordinator serve \
    --da-rpc-url http://localhost:26658 \
    --da-namespace 0000000000000000000000000000000000000000000000000000000000 \
    --da-auth-token eyJhbG... \
    --enable-fallback \
    --fallback-da-type quorum \
    --quorum-validators addr1,addr2,addr3 \
    --quorum-threshold 67

# Using env file
dsdn-coordinator serve --env-file .env.mocha --mock-da
```

---

### `node` — Node Management

```bash
# Register a new storage node
dsdn-coordinator node register --id <ID> --zone <ZONE> --addr <HOST:PORT> [--capacity-gb <GB>]

# List all registered nodes
dsdn-coordinator node list
```

| Flag | Default | Description |
|------|---------|-------------|
| `--id` | *(required)* | Unique node identifier |
| `--zone` | *(required)* | Geographic zone (e.g. `us-east`, `ap-southeast`) |
| `--addr` | *(required)* | Node network address (`host:port`) |
| `--capacity-gb` | `100` | Storage capacity in GB |

#### Examples

```bash
dsdn-coordinator node register --id node-1 --zone us-east --addr 10.0.0.1:50051 --capacity-gb 500
dsdn-coordinator node register --id node-2 --zone ap-southeast --addr 10.0.1.1:50051
dsdn-coordinator node list
```

---

### `object` — Object Operations

```bash
# Register a new object
dsdn-coordinator object register --hash <HASH> --size <BYTES>

# Get object metadata
dsdn-coordinator object get <HASH>

# Get placement nodes for an object
dsdn-coordinator object placement <HASH> [--rf <REPLICATION_FACTOR>]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--hash` | *(required)* | Object content hash |
| `--size` | *(required)* | Object size in bytes |
| `--rf` | `3` | Replication factor (placement only) |

#### Examples

```bash
dsdn-coordinator object register --hash abc123def456 --size 1048576
dsdn-coordinator object get abc123def456
dsdn-coordinator object placement abc123def456 --rf 5
```

---

### `replica` — Replica Management

```bash
# Mark a replica as missing
dsdn-coordinator replica mark-missing --hash <HASH> --node-id <NODE_ID>

# Mark a replica as healed
dsdn-coordinator replica mark-healed --hash <HASH> --node-id <NODE_ID>
```

| Flag | Description |
|------|-------------|
| `--hash` | Object content hash |
| `--node-id` | Node identifier |

#### Examples

```bash
dsdn-coordinator replica mark-missing --hash abc123def456 --node-id node-1
dsdn-coordinator replica mark-healed --hash abc123def456 --node-id node-3
```

---

### `schedule` — Workload Scheduling

```bash
dsdn-coordinator schedule --id <JOB_ID> --cpu <CORES> --mem <GB> --disk <GB>
```

| Flag | Description |
|------|-------------|
| `--id` | Workload identifier |
| `--cpu` | Required CPU cores |
| `--mem` | Required memory in GB |
| `--disk` | Required disk in GB |

#### Example

```bash
dsdn-coordinator schedule --id job-42 --cpu 4 --mem 8 --disk 100
```

---

### `health` / `ready` — Health & Readiness

```bash
# Detailed health check (JSON output)
dsdn-coordinator health

# Readiness probe (exit code 0 = ready, 1 = not ready)
dsdn-coordinator ready
```

The `ready` subcommand is designed for use in orchestration health probes
(Kubernetes, systemd, etc.) — it exits with code `0` if the coordinator is
fully operational, or `1` otherwise.

---

### `fallback` — Fallback DA Management

```bash
# Show fallback status
dsdn-coordinator fallback status

# List pending blobs awaiting reconciliation
dsdn-coordinator fallback pending

# Trigger manual reconciliation
dsdn-coordinator fallback reconcile

# Run state consistency check (read-only)
dsdn-coordinator fallback consistency
```

#### Examples

```bash
# Check if fallback is active
dsdn-coordinator fallback status

# See what's waiting to be reconciled
dsdn-coordinator fallback pending

# Manually push pending blobs to primary DA
dsdn-coordinator fallback reconcile

# Verify internal state consistency
dsdn-coordinator fallback consistency
```

---

### Targeting a Remote Coordinator

All management commands default to `http://127.0.0.1:45831`. To target a
different instance, use the global `--coordinator-url` flag:

```bash
dsdn-coordinator --coordinator-url http://10.0.0.5:45831 node list
dsdn-coordinator --coordinator-url http://10.0.0.5:45831 health
```

Or set the environment variable:

```bash
export DSDN_COORDINATOR_URL=http://10.0.0.5:45831
dsdn-coordinator node list
```

---

## Configuration

The `serve` subcommand accepts configuration through three mechanisms, in order of precedence:

1. **CLI flags** — highest priority (e.g. `--da-rpc-url`)
2. **Environment variables** — fallback (e.g. `DA_RPC_URL`)
3. **Environment files** — loaded via `--env-file` or auto-detected (`.env.mainnet` → `.env`)

Environment files are loaded *before* CLI parsing, so env vars defined in the file
serve as defaults that CLI flags can override.

See the [`serve` CLI reference](#serve--start-the-coordinator-server) for the full
flag/env-var mapping.

---

## HTTP API Reference

The HTTP API is served by `dsdn-coordinator serve` and is also used internally
by the CLI management commands. It remains available for programmatic access.

### Endpoint Summary

| Endpoint | Method | CLI Equivalent |
|----------|--------|----------------|
| `/register` | POST | `node register` |
| `/nodes` | GET | `node list` |
| `/node/{id}` | GET | *(HTTP only)* |
| `/node/{id}/stats` | GET/POST | *(HTTP only)* |
| `/placement/{hash}?rf=N` | GET | `object placement` |
| `/schedule` | POST | `schedule` |
| `/scheduler/config` | POST | *(HTTP only)* |
| `/object/register` | POST | `object register` |
| `/object/{hash}` | GET | `object get` |
| `/replica/mark_missing` | POST | `replica mark-missing` |
| `/replica/mark_healed` | POST | `replica mark-healed` |
| `/da/post` | POST | *(HTTP only)* |
| `/da/metrics` | GET | *(HTTP only)* |
| `/da/routing` | GET | *(HTTP only)* |
| `/fallback/status` | GET | `fallback status` |
| `/fallback/pending` | GET | `fallback pending` |
| `/fallback/reconcile` | POST | `fallback reconcile` |
| `/fallback/consistency` | GET | `fallback consistency` |
| `/health` | GET | `health` |
| `/ready` | GET | `ready` |
| `/system/info` | GET | *(HTTP only)* |

Endpoints marked *(HTTP only)* are accessible via the HTTP API but do not yet
have a dedicated CLI subcommand. They can be accessed directly with `curl` or
any HTTP client.

---

## Components

### Coordinator
Central registry for nodes and objects. Provides node registration and listing,
node runtime stats tracking, object metadata and replica tracking, consistent
hash-based placement, and workload-aware scheduling.

### DARouter
Single entry point for ALL DA operations. Routes requests to primary, secondary,
or emergency DA with health-based automatic failover, metrics tracking per DA
layer, and recovery detection with reconciliation trigger.

### DAHealthMonitor
Monitors DA layer health with periodic health checks (configurable interval),
failover detection (consecutive failures ≥ threshold), recovery detection
(consecutive successes ≥ threshold), and auto-reconciliation trigger on recovery.

### ReconciliationEngine
Syncs fallback blobs to primary DA. Tracks pending blobs from fallback DA with
batch processing, retry logic, and state consistency verification.

### StateMachine
Deterministic event processor. Same events → same state (deterministic),
re-applying events has no effect (idempotent), atomic state transitions.

### Scheduler
Workload-aware node selection with configurable weights for CPU availability,
RAM availability, GPU availability, network latency, and I/O pressure.

---

## Key Invariants

### No Authoritative Local State
**Coordinator state can ALWAYS be reconstructed from DA.**

All state is derived from events on the Data Availability layer. This ensures
Byzantine fault tolerance, deterministic state across all coordinators, full
auditability, and no single point of failure.

### Deterministic Processing
Same events applied in same order always produce identical state.

### Atomic State Updates
State transitions are atomic. Partial state is never exposed.

### DA Fallback Guarantee
When primary DA fails, traffic automatically routes to fallback. Blobs stored in
fallback are tracked. On recovery, blobs reconcile to primary. No data loss
during outages.

---

## Receipt Signing Pipeline (CO.1–CO.9)

The coordinator orchestrates receipt signing as proof that a node performed
work. Receipts flow through a deterministic pipeline before reaching the chain.

### End-to-End Flow

```
1. Usage Proof Verification (CO.3)
   │  Node submits UsageProof with Ed25519 signature.
   │  Coordinator verifies signature + range checks.
   │  Computes reward_base from resource metrics.
   │
   ▼
2. Anti-Self-Dealing Pre-Check (CO.9) [advisory only]
   │  Checks if submitter_address == node owner.
   │  Returns PreCheckResult::Clean or SuspectedSelfDealing.
   │  NEVER blocks signing — monitoring/alerting only.
   │  Chain performs authoritative enforcement.
   │
   ▼
3. Execution Commitment (CO.2) [compute workloads only]
   │  CommitmentBuilder computes Merkle root over execution trace.
   │  Produces ExecutionCommitment with input/output/state hashes.
   │
   ▼
4. Receipt Signing Session (CO.1, CO.4)
   │  ReceiptSigningSession wraps SigningSession.
   │  Tracks receipt_data, execution_commitment, receipt_type.
   │  Registered in MultiCoordinatorState (CO.8).
   │
   ▼
5. Threshold Signing (CO.1, CO.7 mock for tests)
   │  State: CollectingCommitments → CollectingSignatures → Completed
   │  Collect threshold commitments from coordinators.
   │  Collect threshold partial signatures.
   │  Aggregate into final threshold signature.
   │
   ▼
6. Receipt Assembly (CO.5)
   │  assemble_signed_receipt() validates + assembles final ReceiptV1Proto.
   │  13 structural checks (field lengths, type consistency, ranges).
   │  Session removed from active map, receipt added to completed queue.
   │
   ▼
7. DA Publication (CO.6)
   │  Deterministic binary encoding (magic + version + fields).
   │  Published to DA layer via DAClient trait.
   │  Retrievable and decodable with validation on retrieval.
   │
   ▼
8. Chain Handoff
   Chain processes ClaimReward transaction with the published receipt.
   Authoritative anti-self-dealing enforcement occurs here.
```

### Session Lifecycle

Sessions are managed atomically in `MultiCoordinatorState`:

| Phase | Method | State Change |
|-------|--------|-------------|
| Register | `register_receipt_signing()` | Session added to active map |
| Progress | `get_receipt_signing_session_mut()` | Caller drives signing |
| Complete | `complete_receipt_signing()` | Session removed, receipt queued, counter++ |
| Drain | `drain_completed_receipts()` | Receipts taken for DA publication |

Completion is logically atomic: if assembly fails, no state changes.
If assembly succeeds, removal + storage + counter increment happen together.

### Defense-in-Depth

| Layer | Module | Authority | Behavior |
|-------|--------|-----------|----------|
| Coordinator | `precheck_self_dealing` (CO.9) | Advisory | Flags suspicious receipts, never blocks |
| Chain | `ClaimReward` validation | Authoritative | Rejects self-dealing with on-chain proof |

---

## Module Structure

```
crates/coordinator/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs                        # Crate root, Coordinator struct, exports
│   ├── cli.rs                        # CLI definitions (clap), HTTP server, AppState
│   ├── main.rs                       # Entry point (delegates to cli.rs)
│   ├── handlers.rs                   # Extended HTTP handlers
│   ├── scheduler.rs                  # Workload scheduling & scoring
│   ├── da_consumer.rs                # DA event consumption
│   ├── state_machine.rs              # Deterministic event processing
│   ├── state_rebuild.rs              # State reconstruction from DA
│   ├── event_publisher.rs            # Event batching and publishing
│   ├── reconciliation.rs             # Fallback blob reconciliation
│   ├── receipt_publisher.rs          # DA publication + retrieval (CO.6)
│   ├── execution/                    # Execution verification
│   │   ├── mod.rs
│   │   ├── commitment_builder.rs     # ExecutionCommitment + Merkle (CO.2)
│   │   ├── usage_verifier.rs         # Usage proof verification (CO.3)
│   │   └── self_dealing_precheck.rs  # Anti-self-dealing pre-check (CO.9)
│   └── multi/                        # Multi-coordinator consensus
│       ├── mod.rs
│       ├── types.rs                  # CoordinatorId, KeyShare, etc.
│       ├── peer.rs                   # PeerManager, connections
│       ├── message.rs                # Wire protocol messages
│       ├── network.rs                # CoordinatorNetwork trait
│       ├── consensus.rs              # ReceiptConsensus state machine
│       ├── handlers.rs               # Message handlers + state (CO.8)
│       ├── signing.rs                # Threshold signing
│       ├── optimistic.rs             # Optimistic receipts
│       ├── coordinator.rs            # MultiCoordinator orchestrator
│       ├── receipt_signing.rs        # Receipt signing session (CO.1)
│       ├── receipt_trigger.rs        # Signing trigger (CO.4)
│       ├── receipt_assembler.rs      # Receipt assembly (CO.5)
│       └── mock_tss.rs              # Mock TSS [test/feature only] (CO.7)
└── tests/
    ├── da_integration.rs             # DA integration tests
    ├── receipt_signing_tests.rs      # Signing lifecycle tests (CO.10)
    ├── execution_tests.rs            # Execution + usage tests (CO.10)
    └── da_publish_tests.rs           # DA publication + E2E tests (CO.10)
```

---

## Testing

### Unit Tests
```bash
cargo test -p dsdn-coordinator
```

### Integration Tests
```bash
cargo test -p dsdn-coordinator --test receipt_signing_tests
cargo test -p dsdn-coordinator --test execution_tests
cargo test -p dsdn-coordinator --test da_publish_tests
```

### With Mock TSS Feature
```bash
cargo test -p dsdn-coordinator --features mock-tss
```

### Manual Testing with CLI
```bash
# Terminal 1 — start the coordinator
dsdn-coordinator serve --mock-da

# Terminal 2 — interact via CLI
dsdn-coordinator node register --id node-1 --zone us-east --addr 10.0.0.1:50051
dsdn-coordinator node register --id node-2 --zone ap-southeast --addr 10.0.1.1:50051
dsdn-coordinator node list
dsdn-coordinator object register --hash abc123 --size 1048576
dsdn-coordinator object placement abc123 --rf 2
dsdn-coordinator health
dsdn-coordinator fallback status
```

### Test Coverage
```bash
cargo tarpaulin -p dsdn-coordinator --out Html
```

---

## Dependencies

| Crate | Purpose |
|-------|---------|
| `dsdn-common` | Shared types, DALayer trait, MockDA |
| `dsdn-proto` | Protocol buffer definitions |
| `dsdn-tss` | Threshold signature support |
| `clap` | CLI argument parsing |
| `reqwest` | HTTP client (for CLI management commands) |
| `axum` | HTTP server framework |
| `tokio` | Async runtime |
| `parking_lot` | High-performance locks |
| `serde` / `serde_json` | Serialization |
| `tracing` | Structured logging |
| `hex` | Hex encoding/decoding |
| `dotenvy` | Environment file loading |

---

## Version History

| Version | Description |
|---------|-------------|
| 14A | DA Integration Complete |
| 14A.1A.35-39 | DA Fallback System |
| 14A.1A.40 | CLI-based configuration and management |
| 14A.2B.2.11-20 | Multi-Coordinator Consensus |
| 14A.3 | Extended HTTP API |
| CO.1 | Receipt Signing Session |
| CO.2 | Execution Commitment Builder |
| CO.3 | Usage Proof Verification |
| CO.4 | Receipt Signing Trigger |
| CO.5 | Receipt Assembly |
| CO.6 | DA Publication |
| CO.7 | Mock TSS Interface |
| CO.8 | Coordinator State Extension |
| CO.9 | Anti-Self-Dealing Pre-Check |
| CO.10 | Integration Tests & Documentation |

---

## License

MIT License — See workspace root for details.