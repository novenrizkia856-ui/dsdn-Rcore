# DSDN Node Crate (14A)

Storage node implementation untuk DSDN (Decentralized Storage and Data Network).

## Overview

Node adalah komponen penyimpanan dalam jaringan DSDN. Setiap node bertanggung jawab untuk:

- Menyimpan replica data yang ditugaskan
- Mengikuti events dari DA (Data Availability) layer
- Melaporkan status kesehatan
- Memverifikasi integritas data lokal

### Peran Node dalam DSDN

```
┌─────────────────────────────────────────────┐
│                   Node                       │
├─────────────────────────────────────────────┤
│  ┌─────────────┐    ┌──────────────────┐   │
│  │ DAFollower  │───▶│ NodeDerivedState │   │
│  └─────────────┘    └──────────────────┘   │
│         │                    │              │
│         ▼                    ▼              │
│  ┌─────────────┐    ┌──────────────────┐   │
│  │EventProcessor│   │  Local Storage   │   │
│  └─────────────┘    └──────────────────┘   │
└─────────────────────────────────────────────┘
                     │
                     ▼
             ┌───────────────┐
             │  Celestia DA  │
             └───────────────┘
```

Node adalah **DA Follower** - node tidak menentukan state sendiri, melainkan mengikuti events dari Data Availability layer.

## Architecture Summary

### Modules

| Module | Deskripsi |
|--------|-----------|
| `da_follower` | DA subscription dan event processing |
| `event_processor` | Event handling logic |
| `placement_verifier` | Placement verification |
| `delete_handler` | Delete request handling dengan grace period |
| `state_sync` | State synchronization dengan DA |
| `health` | Health reporting |

### State Model

```
NodeDerivedState
├── my_chunks: HashMap<String, ChunkAssignment>
├── coordinator_state: DADerivedState (copy, non-authoritative)
├── last_sequence: u64
├── last_height: u64
├── chunk_sizes: HashMap<String, u64>
└── replica_status: HashMap<String, ReplicaStatus>
```

Semua state dapat direkonstruksi dari DA dengan replay events.

## Startup Flow

```
1. Parse CLI arguments
   └── node_id, da_endpoint, storage_path, http_port

2. Load configuration
   └── Validate all inputs

3. Initialize DA layer
   ├── Production: CelestiaDA
   └── Testing: MockDA

4. Initialize storage
   └── Create storage directory

5. Initialize DA follower
   └── Setup event subscription

6. Start follower
   └── Begin processing DA events

7. Start HTTP server
   └── Expose /health endpoint
```

### Usage

```bash
# Production dengan Celestia
dsdn-node node-1 http://localhost:26658 ./data/node1 8080

# Testing dengan MockDA
dsdn-node node-1 mock ./data/node1 8080

# Auto-generate node ID
dsdn-node auto http://localhost:26658 ./data/node1 8080
```

## Health & Monitoring

### Health Endpoint

```
GET /health
```

Response (healthy):
```json
{
  "node_id": "node-1",
  "da_connected": true,
  "da_last_sequence": 100,
  "da_behind_by": 0,
  "chunks_stored": 50,
  "chunks_pending": 2,
  "chunks_missing": 0,
  "storage_used_gb": 45.5,
  "storage_capacity_gb": 100.0,
  "last_check": 1704729600000
}
```

### Health Criteria

Node dianggap **healthy** jika dan hanya jika:

| Kriteria | Kondisi |
|----------|---------|
| DA Connected | `da_connected == true` |
| No Missing Chunks | `chunks_missing == 0` |
| DA Lag | `da_behind_by < 100` |
| Storage OK | `storage_used_gb <= storage_capacity_gb` |

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Node healthy |
| 503 | Node unhealthy |

## Invariant Keamanan

### ⚠️ KEY INVARIANT

```
Node TIDAK menerima instruksi dari Coordinator via RPC.
Semua perintah datang via DA events.
```

Ini berarti:

1. **Tidak ada RPC mutation** - Node tidak menerima perintah langsung dari coordinator
2. **DA sebagai sumber kebenaran** - Semua perubahan state berasal dari DA events
3. **State dapat direkonstruksi** - Node state dapat direbuild sepenuhnya dari DA
4. **Verifikasi independen** - Node memverifikasi placement dari DA, bukan dari coordinator

### Security Properties

| Property | Guarantee |
|----------|-----------|
| Deterministic | Same events → same state |
| Verifiable | All state derived from DA |
| Rebuildable | State can be reconstructed from DA |
| Non-authoritative | Node does not create authoritative state |

## Batasan Node

### Apa yang Node LAKUKAN:

✅ Menyimpan data yang ditugaskan via DA events  
✅ Mengikuti dan memproses DA events  
✅ Melaporkan health status  
✅ Memverifikasi integritas data lokal  
✅ Mematuhi grace period untuk deletion  

### Apa yang Node TIDAK LAKUKAN:

❌ Menerima perintah via RPC dari coordinator  
❌ Membuat keputusan placement sendiri  
❌ Mengubah state tanpa DA event  
❌ Menghapus data tanpa grace period  
❌ Bertindak sebagai sumber kebenaran  

## Testing

### Unit Tests

```bash
cargo rustsp test -p dsdn-node
```

### Integration Tests

```bash
cargo rustsp test -p dsdn-node --test da_integration
```

### Test Categories

| Category | Deskripsi |
|----------|-----------|
| Node Startup | Init tanpa panic, DA follower aktif |
| End-to-End | DA events → state changes |
| Health | /health endpoint, JSON validity |
| Invariant | No RPC dependency, DA-only commands |

## License

Lihat LICENSE di root repository.