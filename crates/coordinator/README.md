# DSDN Coordinator Crate

The Coordinator is the central orchestration component of DSDN (Decentralized Storage and Data Network). It manages node registry, data placement, workload scheduling, and integration with the Data Availability layer (Celestia).

## Table of Contents

- [Architecture](#architecture)
- [Quick Start](#quick-start)
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
# Run coordinator with mock DA (no Celestia required)
USE_MOCK_DA=true cargo rustsp run -p dsdn-coordinator

# Coordinator listens on http://127.0.0.1:45831
```

### Production Mode (Celestia)

```bash
# Set required environment variables
export DA_RPC_URL="http://localhost:26658"
export DA_NAMESPACE="0000000000000000000000000000000000000000000000000000000000"
export DA_AUTH_TOKEN="your-auth-token"
export DA_NETWORK="mainnet"

# Run coordinator
cargo rustsp run -p dsdn-coordinator --release
```

### Quick Test

```bash
# Register a node
curl -X POST http://127.0.0.1:45831/register \
  -H "Content-Type: application/json" \
  -d '{"id":"node-1","zone":"zone-a","addr":"10.0.0.1:50051","capacity_gb":100}'

# List nodes
curl http://127.0.0.1:45831/nodes

# Check system info
curl http://127.0.0.1:45831/system/info

# Health check
curl http://127.0.0.1:45831/health
```

---

## Configuration

### Environment Variables

#### Primary DA (Celestia)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DA_RPC_URL` | Yes* | - | Celestia light node RPC endpoint |
| `DA_NAMESPACE` | Yes* | - | 58-character hex namespace |
| `DA_AUTH_TOKEN` | Yes* | - | Authentication token (mainnet) |
| `DA_NETWORK` | No | `local` | Network: `mainnet`, `mocha`, `local` |
| `DA_TIMEOUT_MS` | No | `30000` | Operation timeout in ms |
| `DA_RETRY_COUNT` | No | `3` | Retries for failed operations |
| `DA_RETRY_DELAY_MS` | No | `1000` | Delay between retries |
| `USE_MOCK_DA` | No | `false` | Use MockDA for development |

*Not required if `USE_MOCK_DA=true`

#### Fallback DA

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ENABLE_FALLBACK` | No | `false` | Enable fallback DA system |
| `FALLBACK_DA_TYPE` | No | `none` | Type: `none`, `quorum`, `emergency` |
| `QUORUM_VALIDATORS` | If quorum | - | Comma-separated validator addresses |
| `QUORUM_THRESHOLD` | No | `67` | Quorum percentage (1-100) |
| `QUORUM_SIGNATURE_TIMEOUT_MS` | No | `5000` | Signature collection timeout |
| `EMERGENCY_DA_URL` | If emergency | - | Emergency DA endpoint URL |

#### Reconciliation

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `RECONCILE_BATCH_SIZE` | No | `10` | Blobs per reconciliation batch |
| `RECONCILE_RETRY_DELAY_MS` | No | `1000` | Delay between retries |
| `RECONCILE_MAX_RETRIES` | No | `3` | Max retry attempts per blob |
| `RECONCILE_PARALLEL` | No | `false` | Enable parallel processing |

#### HTTP Server

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `COORDINATOR_HOST` | No | `127.0.0.1` | HTTP server bind address |
| `COORDINATOR_PORT` | No | `45831` | HTTP server port |

---

## HTTP API Reference

### Node Management

#### Register Node
```http
POST /register
Content-Type: application/json

{
  "id": "node-1",
  "zone": "zone-a",
  "addr": "10.0.0.1:50051",
  "capacity_gb": 100
}

Response: {"ok": true}
```

#### List All Nodes
```http
GET /nodes

Response: [
  {"id": "node-1", "zone": "zone-a", "addr": "10.0.0.1:50051", "capacity_gb": 100, "meta": {}},
  ...
]
```

#### Get Single Node
```http
GET /node/{id}

Response: {"id": "node-1", "zone": "zone-a", "addr": "10.0.0.1:50051", "capacity_gb": 100, "meta": {}}
```

#### Get Node Stats
```http
GET /node/{id}/stats

Response: {
  "node_id": "node-1",
  "found": true,
  "stats": {
    "cpu_free": 0.75,
    "ram_free_mb": 8192.0,
    "gpu_free": 0.5,
    "latency_ms": 5.0,
    "io_pressure": 0.1
  }
}
```

#### Update Node Stats
```http
POST /node/{id}/stats
Content-Type: application/json

{
  "cpu_free": 0.75,
  "ram_free_mb": 8192.0,
  "gpu_free": 0.5,
  "latency_ms": 5.0,
  "io_pressure": 0.1
}

Response: {"ok": true, "node_id": "node-1"}
```

### Placement & Scheduling

#### Get Placement for Hash
```http
GET /placement/{hash}?rf=3

Response: ["node-1", "node-3", "node-5"]
```

#### Schedule Workload
```http
POST /schedule
Content-Type: application/json

{
  "cpu_req": 0.2,
  "ram_req_mb": 1024.0,
  "gpu_req": null,
  "max_latency_ms": 10.0,
  "io_tolerance": null
}

Response: {"node_id": "node-2"}
```

#### Set Scheduler Config
```http
POST /scheduler/config
Content-Type: application/json

{
  "w_cpu": 1.0,
  "w_ram": 1.5,
  "w_gpu": 0.5,
  "w_latency": 1.0,
  "w_io": 0.8
}

Response: {"ok": true, "message": "scheduler config updated", "config": {...}}
```

### Object Management

#### Register Object
```http
POST /object/register
Content-Type: application/json

{
  "hash": "abc123def456...",
  "size": 1048576
}

Response: {"ok": true}
```

#### Get Object
```http
GET /object/{hash}

Response: {"hash": "abc123...", "size": 1048576, "replicas": ["node-1", "node-2"]}
```

#### Mark Replica Missing
```http
POST /replica/mark_missing
Content-Type: application/json

{
  "hash": "abc123...",
  "node_id": "node-1"
}

Response: {"ok": true}
```

#### Mark Replica Healed
```http
POST /replica/mark_healed
Content-Type: application/json

{
  "hash": "abc123...",
  "node_id": "node-3"
}

Response: {"ok": true}
```

### DA (Data Availability)

#### Post Blob
```http
POST /da/post
Content-Type: application/json

{
  "data_hex": "68656c6c6f20776f726c64"
}

Response: {
  "success": true,
  "commitment": "abc123...",
  "height": 12345
}
```

#### Get DA Metrics
```http
GET /da/metrics

Response: {
  "available": true,
  "post_count": 100,
  "get_count": 50,
  "error_count": 2,
  "health_check_count": 1000,
  "retry_count": 5,
  "avg_post_latency_us": 1500,
  "avg_get_latency_us": 800
}
```

#### Get DA Routing State
```http
GET /da/routing

Response: {
  "current_state": "primary",
  "primary_healthy": true,
  "secondary_healthy": false,
  "emergency_healthy": false,
  "fallback_active": false,
  "pending_reconcile": 0
}
```

### Fallback Management

#### Get Fallback Status
```http
GET /fallback/status

Response: {
  "current_status": "primary_healthy",
  "fallback_active": false,
  "fallback_reason": null,
  "pending_reconcile_count": 0,
  "last_fallback_at": null
}
```

#### Get Pending Blobs
```http
GET /fallback/pending

Response: [
  {
    "blob_id": "abc123...",
    "source_da": "secondary",
    "target_da": "primary",
    "stored_at": 1704067200000,
    "retry_count": 0,
    "last_error": null
  }
]
```

#### Trigger Reconciliation
```http
POST /fallback/reconcile

Response: {
  "success": true,
  "blobs_processed": 5,
  "blobs_reconciled": 5,
  "blobs_failed": 0,
  "duration_ms": 1500,
  "errors": []
}
```

#### Get Consistency Report
```http
GET /fallback/consistency

Response: {
  "is_consistent": true,
  "items_verified": 100,
  "inconsistencies_found": 0,
  "details": [],
  "verified_at": 1704067200000
}
```

### System & Health

#### Health Check
```http
GET /health

Response: {
  "status": "healthy (routing: primary)",
  "da_available": true,
  "da_health": "Ok(Healthy)",
  "metrics": {
    "post_count": 100,
    "get_count": 50,
    ...
  }
}
```

#### Readiness Check
```http
GET /ready

Response: 200 OK (if ready) or 503 Service Unavailable
```

#### System Info
```http
GET /system/info

Response: {
  "version": "0.1.0",
  "node_count": 5,
  "da_status": "Ok(Healthy)",
  "routing_state": "primary",
  "fallback_active": false
}
```

### Endpoint Summary Table

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/register` | POST | Register node |
| `/nodes` | GET | List all nodes |
| `/node/{id}` | GET | Get single node |
| `/node/{id}/stats` | GET | Get node stats |
| `/node/{id}/stats` | POST | Update node stats |
| `/placement/{hash}` | GET | Get placement for hash |
| `/schedule` | POST | Schedule workload |
| `/scheduler/config` | POST | Set scheduler config |
| `/object/register` | POST | Register object |
| `/object/{hash}` | GET | Get object |
| `/replica/mark_missing` | POST | Mark replica missing |
| `/replica/mark_healed` | POST | Mark replica healed |
| `/da/post` | POST | Post blob to DA |
| `/da/metrics` | GET | DA metrics |
| `/da/routing` | GET | DA routing state |
| `/fallback/status` | GET | Fallback status |
| `/fallback/pending` | GET | Pending blobs |
| `/fallback/reconcile` | POST | Trigger reconciliation |
| `/fallback/consistency` | GET | Consistency report |
| `/health` | GET | Health check |
| `/ready` | GET | Readiness check |
| `/system/info` | GET | System info |

---

## Components

### Coordinator
Central registry for nodes and objects. Provides:
- Node registration and listing
- Node runtime stats tracking
- Object metadata and replica tracking
- Consistent hash-based placement
- Workload-aware scheduling

### DARouter
Single entry point for ALL DA operations. Features:
- Routes requests to primary, secondary, or emergency DA
- Health-based automatic failover
- Metrics tracking per DA layer
- Recovery detection and reconciliation trigger

### DAHealthMonitor
Monitors DA layer health. Responsibilities:
- Periodic health checks (configurable interval)
- Failover detection (consecutive failures >= threshold)
- Recovery detection (consecutive successes >= threshold)
- Auto-reconciliation trigger on recovery

### ReconciliationEngine
Syncs fallback blobs to primary DA. Features:
- Tracks pending blobs from fallback DA
- Batch processing with configurable size
- Retry logic with max attempts
- State consistency verification

### StateMachine
Deterministic event processor. Guarantees:
- Same events → same state (deterministic)
- Re-applying events has no effect (idempotent)
- Atomic state transitions

### Scheduler
Workload-aware node selection. Configurable weights:
- `w_cpu`: CPU availability weight
- `w_ram`: RAM availability weight
- `w_gpu`: GPU availability weight
- `w_latency`: Network latency weight
- `w_io`: I/O pressure weight

---

## Key Invariants

### No Authoritative Local State
**Coordinator state can ALWAYS be reconstructed from DA.**

All state is derived from events on the Data Availability layer. This ensures:
- Byzantine fault tolerance
- Deterministic state across all coordinators
- Full auditability
- No single point of failure

### Deterministic Processing
Same events applied in same order always produce identical state.

### Atomic State Updates
State transitions are atomic. Partial state is never exposed.

### DA Fallback Guarantee
When primary DA fails:
1. Traffic automatically routes to fallback
2. Blobs stored in fallback are tracked
3. On recovery, blobs reconcile to primary
4. No data loss during outages

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
│   ├── main.rs                       # HTTP server, DARouter, AppState
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

### Manual API Testing
```bash
# Start coordinator
USE_MOCK_DA=true cargo run -p dsdn-coordinator

# Run test script (see COORDINATOR_API_USAGE.md)
./test_coordinator.sh
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
| `axum` | HTTP server framework |
| `tokio` | Async runtime |
| `parking_lot` | High-performance locks |
| `serde` / `serde_json` | Serialization |
| `tracing` | Structured logging |
| `hex` | Hex encoding/decoding |

---

## Version History

| Version | Description |
|---------|-------------|
| 14A | DA Integration Complete |
| 14A.1A.35-39 | DA Fallback System |
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

MIT License - See workspace root for details.