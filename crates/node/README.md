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

Node adalah **DA Follower** — node tidak menentukan state sendiri, melainkan mengikuti events dari Data Availability layer.

## Quick Start

### 1. Siapkan `.env.mainnet`

Buat file `.env.mainnet` di root directory project:

```env
# ── Node Identity ──
NODE_ID=auto
NODE_STORAGE_PATH=./data/node1
NODE_HTTP_PORT=45831

# ── DA Layer (Celestia) ──
DA_RPC_URL=http://localhost:26658
DA_NAMESPACE=0000000000000000000000000000000000000000000000000000000000
DA_AUTH_TOKEN=your_celestia_auth_token_here
DA_NETWORK=mainnet
DA_TIMEOUT_MS=30000
DA_RETRY_COUNT=3

# ── Optional ──
# USE_MOCK_DA=true          # Gunakan MockDA untuk development
# DSDN_ENV_FILE=.env.custom # Custom env file path
```

### 2. Jalankan Node

```bash
# Cara paling simpel — otomatis baca .env.mainnet
dsdn-node run

# Atau eksplisit
dsdn-node run env
```

### 3. Cek Status

```bash
dsdn-node health
dsdn-node status
```

## CLI Reference

### `dsdn-node run`

Start node. Ini adalah command utama.

```bash
# Mode 1: Environment (Production) — DEFAULT
# Baca config dari .env.mainnet secara otomatis
dsdn-node run
dsdn-node run env

# Mode 2: CLI Arguments (Development)
dsdn-node run <node-id|auto> <da-endpoint|mock> <storage-path> <http-port>

# Contoh:
dsdn-node run node-1 http://localhost:26658 ./data/node1 45831
dsdn-node run auto mock ./data/node1 45831
```

Kalau tidak ada subcommand, `dsdn-node` otomatis menjalankan `run` dalam env mode:

```bash
# Ini sama saja:
dsdn-node
dsdn-node run
dsdn-node run env
```

### `dsdn-node status`

Query status dari node yang sedang berjalan via HTTP `/status` endpoint.

```bash
dsdn-node status              # Default port dari NODE_HTTP_PORT atau 45831
dsdn-node status --port 45831  # Custom port
dsdn-node status -p 45831      # Shorthand
```

### `dsdn-node health`

Query health dari node yang sedang berjalan via HTTP `/health` endpoint.

```bash
dsdn-node health              # Default port
dsdn-node health --port 45831  # Custom port
```

### `dsdn-node info`

Tampilkan build info dan konfigurasi environment saat ini. Berguna untuk debugging apakah `.env.mainnet` terbaca dengan benar.

```bash
dsdn-node info
```

Output contoh:

```
═══════════════════════════════════════════════════════════════
                    DSDN Node Info
═══════════════════════════════════════════════════════════════
Version:        dsdn-node v0.1.0
Env file:       /path/to/project/.env.mainnet

── Current Configuration (from env) ──
NODE_ID:            auto
NODE_STORAGE_PATH:  ./data/node1
NODE_HTTP_PORT:     45831
DA_RPC_URL:         http://localhost:26658
DA_NAMESPACE:       000000000000000000000000000000000000000000000000000000000
DA_NETWORK:         mainnet
DA_AUTH_TOKEN:      (set)
USE_MOCK_DA:        false
═══════════════════════════════════════════════════════════════
```

### `dsdn-node version`

Tampilkan version string.

```bash
dsdn-node version
dsdn-node --version
dsdn-node -V
```

### `dsdn-node help`

Tampilkan usage dan daftar command.

```bash
dsdn-node help
dsdn-node --help
dsdn-node -h
```

## Environment File Loading

Node otomatis load environment variables dari file, dengan priority order yang sama dengan coordinator:

| Priority | Source | Keterangan |
|----------|--------|------------|
| 1 | `DSDN_ENV_FILE` env var | Custom path, jika di-set |
| 2 | `.env.mainnet` | Production default — **DSDN defaults to mainnet** |
| 3 | `.env` | Fallback untuk development |

Loading terjadi otomatis di awal sebelum apapun diproses. Jika file tidak ditemukan, node tetap jalan menggunakan environment variables yang sudah di-set secara manual.

### Contoh Setup

**Production (mainnet):**
```bash
# Cukup buat .env.mainnet, lalu:
dsdn-node run
```

**Development (mock DA):**
```bash
# .env
USE_MOCK_DA=true
NODE_ID=dev-node
NODE_STORAGE_PATH=./data/dev
NODE_HTTP_PORT=45831

dsdn-node run
```

**Custom env file:**
```bash
DSDN_ENV_FILE=.env.staging dsdn-node run
```

## Environment Variables

### Required (env mode)

| Variable | Deskripsi |
|----------|-----------|
| `NODE_ID` | Unique node identifier, atau `auto` untuk UUID otomatis |
| `NODE_STORAGE_PATH` | Path directory untuk penyimpanan data |
| `NODE_HTTP_PORT` | Port HTTP server untuk observability endpoints |
| `DA_RPC_URL` | Celestia light node RPC endpoint |
| `DA_NAMESPACE` | 58-character hex namespace |
| `DA_AUTH_TOKEN` | Authentication token (wajib untuk mainnet) |

### Optional

| Variable | Default | Deskripsi |
|----------|---------|-----------|
| `DA_NETWORK` | `mainnet` | Network identifier: `mainnet`, `mocha`, `local` |
| `DA_TIMEOUT_MS` | `30000` | Operation timeout dalam milliseconds |
| `DA_RETRY_COUNT` | `3` | Jumlah retry untuk operasi DA yang gagal |
| `USE_MOCK_DA` | `false` | Gunakan MockDA untuk development |
| `DSDN_ENV_FILE` | — | Custom path ke env file |

## Architecture Summary

### Modules

| Module | Deskripsi |
|--------|-----------|
| `da_follower` | DA subscription, event processing, source transitions |
| `event_processor` | Event handling logic dengan fallback detection |
| `placement_verifier` | Placement verification |
| `delete_handler` | Delete request handling dengan grace period |
| `state_sync` | State synchronization dengan DA |
| `health` | Health reporting dengan fallback awareness |
| `multi_da_source` | Multi-DA source abstraction (Primary/Secondary/Emergency) |
| `metrics` | Node fallback metrics untuk Prometheus export |
| `handlers` | Axum HTTP API handlers (read-only observability) |

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

### Multi-DA Source Architecture

Node mendukung fault-tolerant Multi-DA source dengan tiga tier:

| Source | Priority | Role |
|--------|----------|------|
| Primary (Celestia) | 1 | Main DA source, selalu diutamakan |
| Secondary (Backup) | 2 | Digunakan ketika Primary gagal |
| Emergency | 3 | Last resort ketika keduanya gagal |

Transisi antar source bersifat atomic — berhasil sepenuhnya atau rollback sepenuhnya.

## HTTP Endpoints

Semua endpoint bersifat **READ-ONLY** (observability only). Node menerima command hanya via DA events, bukan via HTTP.

| Endpoint | Method | Deskripsi |
|----------|--------|-----------|
| `/health` | GET | Health check (200 = healthy, 503 = unhealthy) |
| `/ready` | GET | Readiness check (DA connected?) |
| `/info` | GET | Node info (version, node_id, uptime) |
| `/status` | GET | Status lengkap (state, DA, storage) |
| `/state` | GET | Current NodeDerivedState |
| `/state/fallback` | GET | Fallback state detail |
| `/state/assignments` | GET | Chunk assignments |
| `/da/status` | GET | DA layer status |
| `/metrics` | GET | Metrics JSON |
| `/metrics/prometheus` | GET | Metrics format Prometheus |

### Health Endpoint Detail

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

## Startup Flow

```
1. Load .env.mainnet (atau custom env file)
   └── Priority: DSDN_ENV_FILE > .env.mainnet > .env

2. Parse subcommand
   ├── run   → Start node
   ├── status → Query running node
   ├── health → Query running node health
   ├── info   → Show config info
   └── version → Show version

3. [run] Parse configuration
   ├── env mode  → Baca dari environment variables
   └── CLI mode  → Baca dari arguments

4. [run] Validate configuration
   └── Production validation jika DA_NETWORK=mainnet

5. [run] Initialize DA layer
   ├── Production: CelestiaDA + startup health check
   └── Testing: MockDA

6. [run] Initialize storage
   └── Buat storage directory jika belum ada

7. [run] Initialize DA follower
   └── Setup event subscription + health monitoring

8. [run] Start HTTP server (Axum)
   └── Expose observability endpoints

9. [run] Wait for shutdown (Ctrl+C)
   └── Graceful shutdown semua task
```

## Backward Compatibility

Command lama tetap berjalan:

```bash
# Format lama (masih didukung):
dsdn-node node-1 http://localhost:26658 ./data/node1 45831
dsdn-node auto mock ./data/node1 45831
dsdn-node env

# Format baru (recommended):
dsdn-node run node-1 http://localhost:26658 ./data/node1 45831
dsdn-node run auto mock ./data/node1 45831
dsdn-node run env
dsdn-node run   # default env mode
```

## Invariant Keamanan

### ⚠️ KEY INVARIANT

```
Node TIDAK menerima instruksi dari Coordinator via RPC.
Semua perintah datang via DA events.
```

Ini berarti:

1. **Tidak ada RPC mutation** — Node tidak menerima perintah langsung dari coordinator
2. **DA sebagai sumber kebenaran** — Semua perubahan state berasal dari DA events
3. **State dapat direkonstruksi** — Node state dapat direbuild sepenuhnya dari DA
4. **Verifikasi independen** — Node memverifikasi placement dari DA, bukan dari coordinator

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
✅ Melaporkan health status via HTTP
✅ Memverifikasi integritas data lokal
✅ Mematuhi grace period untuk deletion
✅ Auto-load config dari `.env.mainnet`

### Apa yang Node TIDAK LAKUKAN:

❌ Menerima perintah via RPC dari coordinator
❌ Membuat keputusan placement sendiri
❌ Mengubah state tanpa DA event
❌ Menghapus data tanpa grace period
❌ Bertindak sebagai sumber kebenaran

## Dependencies

Dependencies tambahan yang dibutuhkan di `Cargo.toml`:

```toml
[dependencies]
dotenvy = "0.15"          # .env.mainnet file loading
reqwest = { version = "0.12", features = ["json"] }  # CLI status/health commands
serde_json = "1"          # JSON pretty-print untuk CLI output
```

## Testing

### Unit Tests

```bash
cargo test -p dsdn-node
```

### Integration Tests

```bash
cargo test -p dsdn-node --test da_integration
```

### Test Categories

| Category | Deskripsi |
|----------|-----------|
| Node Startup | Init tanpa panic, DA follower aktif |
| Config Parsing | CLI args, env mode, backward compat |
| End-to-End | DA events → state changes |
| Health | `/health` endpoint, JSON validity |
| CLI Commands | `status`, `health`, `info`, `version` |
| Invariant | No RPC dependency, DA-only commands |

## License

Lihat LICENSE di root repository.