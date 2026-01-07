# DSDN Coordinator Crate

The Coordinator is the central orchestration component of DSDN (Decentralized Storage and Data Network). It manages node registry, data placement, workload scheduling, and integration with the Data Availability layer.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           COORDINATOR                                   │
│                                                                         │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐     │
│  │   DAConsumer    │───▶│  StateMachine   │───▶│ DADerivedState  │     │
│  │ (Event Ingest)  │    │ (Event Apply)   │    │ (Authoritative) │     │
│  └────────┬────────┘    └─────────────────┘    └────────┬────────┘     │
│           │                                              │              │
│           │ subscribe                          read-only │              │
│           │                                              ▼              │
│  ┌────────┴────────┐                          ┌─────────────────┐      │
│  │    DALayer      │◀─────────────────────────│   Scheduler     │      │
│  │  (Celestia)     │         publish          │   Placement     │      │
│  └────────┬────────┘                          └─────────────────┘      │
│           │                                              ▲              │
│           │                                              │              │
│  ┌────────┴────────┐    ┌─────────────────┐             │              │
│  │ EventPublisher  │───▶│  StateRebuilder │─────────────┘              │
│  │ (Event Write)   │    │   (Recovery)    │     rebuild                │
│  └─────────────────┘    └─────────────────┘                            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Components

### DAConsumer
Subscribes to events from the Data Availability layer (e.g., Celestia). Receives blob events and forwards them to the StateMachine for processing.

### StateMachine
Deterministic, idempotent event processor. Applies DA events to build and maintain `DADerivedState`. Guarantees:
- Same events always produce same state
- Re-applying events has no effect (idempotent)
- State is never partially corrupted

### DADerivedState
The authoritative state derived from DA events. Contains:
- **node_registry**: Registered storage nodes
- **chunk_map**: Declared data chunks and metadata
- **replica_map**: Replica locations for each chunk
- **zone_map**: Zone membership for placement decisions

### StateRebuilder
Reconstructs state from DA history. Used for:
- New node bootstrap
- Crash recovery
- State verification and audit

### EventPublisher
Batches and publishes new events to the DA layer. Guarantees:
- No event loss
- Atomic batch publishing
- Automatic periodic flushing

### Scheduler
Workload-aware node selection using configurable scoring weights.

## Lifecycle

### Event Ingest
1. DAConsumer subscribes to DA layer
2. Blob events received via stream
3. Events decoded and validated
4. StateMachine applies events
5. DADerivedState updated

### State Update
1. Event received (e.g., NodeRegistered, ChunkDeclared)
2. Event handler validates and processes
3. State maps updated atomically
4. Sequence number incremented

### Event Publish
1. Coordinator action creates new event
2. Event queued in EventPublisher
3. Batch formed when size threshold reached
4. Batch encoded deterministically
5. Blob posted to DA layer
6. Pending cleared on success

### Recovery & Rebuild
1. Coordinator starts (or restarts)
2. StateRebuilder fetches historical blobs from DA
3. Events replayed in sequence order
4. State reconstructed identically to live state
5. Normal operation resumes

## Key Invariants

### No Authoritative Local State
**Coordinator state can ALWAYS be reconstructed from DA.**

All state is derived from events on the Data Availability layer. There is no hidden local state that cannot be recovered. This ensures:

- Byzantine fault tolerance
- Deterministic state across all coordinators
- Full auditability
- No single point of failure

### Deterministic Processing
Same events applied in same order always produce identical state. This is verified by checksum comparison after rebuild.

### Atomic State Updates
State transitions are atomic. On failure, state rolls back to the last consistent point. Partial state is never exposed.

## Usage

### Basic Coordinator Operations

```rust
// Create coordinator with DA-derived state
let coordinator = Coordinator::new();

// State comes from DA events, not local operations
// All reads go through DADerivedState
```

### Event Processing

```rust
// StateMachine processes events deterministically
let mut sm = StateMachine::new();
sm.apply_event(event)?;

// Query state (read-only)
let state = sm.state();
let node = state.get_node("node-1");
let chunk = state.get_chunk(hash);
```

### Publishing Events

```rust
// EventPublisher batches and writes to DA
let publisher = EventPublisher::new(da);
publisher.publish(event)?;
publisher.flush()?;
```

### Recovery

```rust
// StateRebuilder reconstructs from DA
let rebuilder = StateRebuilder::new(da, 0, None);
let state = rebuilder.rebuild()?;
```

## Testing

Run unit tests:
```bash
cargo test -p dsdn-coordinator
```

Run integration tests:
```bash
cargo test -p dsdn-coordinator --test da_integration
```

## Module Structure

```
crates/coordinator/
├── src/
│   ├── lib.rs              # Crate root, Coordinator struct
│   ├── scheduler.rs        # Workload scheduling
│   ├── da_consumer.rs      # DA event consumption
│   ├── state_machine.rs    # Deterministic event processing
│   ├── state_rebuild.rs    # State reconstruction
│   └── event_publisher.rs  # Event batching and publishing
└── tests/
    └── da_integration.rs   # Integration tests
```

## Dependencies

- `dsdn_common`: Shared types, DALayer trait, MockDA for testing
- `parking_lot`: High-performance synchronization primitives
- `tokio`: Async runtime for background tasks
- `tracing`: Structured logging

## Version

Coordinator Crate Version: 14A (DA Integration Complete)