# DSDN Storage Crate

Storage layer untuk DSDN (Decentralized Storage & Data Network) dengan DA (Data Availability) awareness.

## Overview

Crate `dsdn-storage` menyediakan:

- **Storage trait** dan implementasi (local filesystem)
- **DA-aware storage wrapper** untuk integrasi dengan DA layer
- **Chunk management** (chunking, storage, retrieval)
- **Storage proof** untuk challenge-response verification
- **Garbage collection** berbasis DA events
- **Recovery** dari peer nodes
- **Metrics** untuk observability
- **Event emission** untuk logging dan monitoring

### Peran di Arsitektur DSDN

```text
┌─────────────────────────────────────────────────────────┐
│                     DSDN Node                            │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │
│  │ Coordinator │  │    Node     │  │     Storage     │ │
│  │  (DA pub)   │  │ (DA follow) │  │   (DA-aware)    │ │
│  └─────────────┘  └─────────────┘  └─────────────────┘ │
│         │                │                  │           │
│         ▼                ▼                  ▼           │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Celestia DA Layer                   │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## DA Awareness

**Storage BUKAN sumber kebenaran.** Semua metadata berasal dari DA layer.

### Prinsip Fundamental

1. **Metadata derived from DA**: Semua chunk metadata (assignment, replicas, commitments) diturunkan dari DA events
2. **State reconstructable**: State storage dapat direkonstruksi sepenuhnya dari DA
3. **No local authority**: Storage lokal tidak membuat keputusan tanpa dasar DA

### Flow Metadata

```text
Celestia DA
    │
    ▼
ChunkDeclared event ─────► declared_chunks
                               │
                               ▼
                    sync_metadata_from_da()
                               │
                               ▼
                          chunk_metadata (derived)
```

## Lifecycle Chunk

### 1. Declare

Chunk dideklarasikan di DA layer dengan metadata:
- Hash
- Size
- Commitment (SHA3-256)
- Target replication factor

### 2. Store

Data chunk disimpan di storage lokal:
- Commitment diverifikasi
- Metadata di-sync dari DA

### 3. Verify

Commitment verification:
- SHA3-256(data) == da_commitment
- Challenge-response proof generation

### 4. Replicate

Replica assignment dari DA:
- ReplicaAdded events
- current_rf tracking
- Placement verification

### 5. Delete

Delete request dari DA:
- DeleteRequested event
- Grace period
- GC scan & collect

### 6. Garbage Collection

GC berbasis DA events:
- **Deleted**: DeleteRequested + grace period expired
- **Orphaned**: Not assigned to this node
- **Corrupted**: Commitment mismatch

```text
scan() ──► GCScanResult ──► collect() ──► Deleted chunks
```

## Recovery & Safety

### Recovery Process

1. Identify missing chunks (assigned via DA tapi tidak di storage)
2. Fetch dari peer nodes
3. Verify commitment sebelum store
4. Tidak overwrite existing chunks

### Safety Guarantees

- Recovery **HANYA** untuk chunks yang assigned via DA
- Data **WAJIB** diverifikasi sebelum disimpan
- **NO OVERWRITE** untuk existing chunks
- Recovery berbasis DA assignment, bukan heuristik

## Invariants

Crate ini menjamin invariant berikut:

1. **Metadata Derivation**: Semua chunk metadata dapat direkonstruksi dari DA events
2. **No Unauthorized Storage**: Tidak ada chunk disimpan tanpa dasar DA
3. **Commitment Integrity**: Setiap chunk yang disimpan memiliki commitment yang valid
4. **Recovery Safety**: Recovery hanya untuk assigned chunks dengan verifikasi
5. **GC Safety**: GC hanya menghapus chunks yang eligible via DA events
6. **No Local Authority**: Storage tidak membuat keputusan tanpa dasar DA
7. **Idempotent Sync**: Sync metadata dari DA adalah idempotent
8. **Event Isolation**: Events tidak mempengaruhi correctness storage

## Modules

| Module | Deskripsi |
|--------|-----------|
| `store` | Storage trait abstraction |
| `localfs` | Local filesystem implementation |
| `chunker` | File chunking utilities |
| `da_storage` | DA-aware storage wrapper |
| `storage_proof` | Proof generation untuk challenges |
| `gc` | Garbage collection |
| `recovery` | Chunk recovery dari peers |
| `metrics` | Storage health metrics |
| `events` | Storage event emission |
| `rpc` | gRPC services untuk chunk transfer |

## Usage

```rust
use dsdn_storage::{DAStorage, Storage, StorageMetrics};
use dsdn_common::MockDA;
use std::sync::Arc;

// Create DA-aware storage
let inner = Arc::new(LocalFsStorage::new("/path/to/storage")?);
let da = Arc::new(MockDA::new());
let storage = DAStorage::new(inner, da);

// Receive DA events
storage.receive_chunk_declared(event);
storage.sync_metadata_from_da()?;

// Store chunk
storage.put_chunk_with_meta(hash, data, commitment)?;

// Get metrics
let metrics = StorageMetrics::collect(&storage);
```

## Testing

Integration tests di `tests/da_integration.rs` menguji:

1. **DA → Metadata Derivation**: Metadata derived dari DA events
2. **Recovery Roundtrip**: Recovery dengan verifikasi
3. **GC Safety**: GC respects DA assignment
4. **Metrics Consistency**: Metrics match actual state
5. **Event Emission**: Events tidak affect behavior

```bash
cargo test --package dsdn-storage
```

## Version

Tahap: 14A (Final)