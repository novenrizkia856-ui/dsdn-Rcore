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

### Development (Mock DA)

```bash
dsdn-node run --mock-da
```

### Production (Celestia)

```bash
dsdn-node run \
    --node-id node-1 \
    --da-rpc-url http://localhost:26658 \
    --da-namespace 0000000000000000000000000000000000000000000064736E6474657374 \
    --da-auth-token <TOKEN> \
    --da-network mainnet \
    --storage-path ./data/node1 \
    --http-port 45832
```

### Cek Status (terminal kedua)

```bash
dsdn-node health
dsdn-node status
dsdn-node store stats
```

## Configuration

Node mendukung tiga tier konfigurasi (sama seperti coordinator):

| Priority | Source | Contoh |
|----------|--------|--------|
| 1 (highest) | CLI flags | `--da-rpc-url http://...` |
| 2 | Environment variables | `DA_RPC_URL=http://...` |
| 3 (lowest) | `.env` file | File `.env.mainnet` atau `.env` |

Setiap CLI flag punya env-var fallback. Bisa pakai `.env.mainnet` tanpa CLI flags, atau override via flags.

### Environment File Loading

| Priority | File | Keterangan |
|----------|------|------------|
| 1 | `DSDN_ENV_FILE` env var | Custom path, jika di-set |
| 2 | `.env.mainnet` | Production default — **DSDN defaults to mainnet** |
| 3 | `.env` | Fallback untuk development |

### Contoh `.env.mainnet`

```env
NODE_ID=auto
NODE_STORAGE_PATH=./data/node1
NODE_HTTP_PORT=45832
DA_RPC_URL=http://localhost:26658
DA_NAMESPACE=0000000000000000000000000000000000000000000064736E6474657374
DA_AUTH_TOKEN=your_celestia_auth_token_here
DA_NETWORK=mainnet
```

Setelah `.env.mainnet` ada, cukup:

```bash
dsdn-node run
```

## CLI Reference

### `dsdn-node run`

Start node server. Ini adalah command utama.

```bash
dsdn-node run [OPTIONS]
```

Tanpa subcommand, `dsdn-node` otomatis menjalankan `run`:

```bash
# Semua ini equivalent:
dsdn-node
dsdn-node run
```

**Node Identity:**

| Flag | Env Var | Default | Deskripsi |
|------|---------|---------|-----------|
| `--node-id` | `NODE_ID` | `auto` | Node identifier (`auto` = UUID) |

**Storage:**

| Flag | Env Var | Default | Deskripsi |
|------|---------|---------|-----------|
| `--storage-path` | `NODE_STORAGE_PATH` | `./data` | Storage directory path |
| `--storage-capacity-gb` | `NODE_STORAGE_CAPACITY_GB` | `100` | Storage capacity in GB |

**Network Ports:**

| Flag | Env Var | Default | Deskripsi |
|------|---------|---------|-----------|
| `--http-port` | `NODE_HTTP_PORT` | `45832` | HTTP server port |
| `--grpc-port` | `NODE_GRPC_PORT` | http + 1000 | gRPC storage server port |

**Primary DA (Celestia):**

| Flag | Env Var | Default | Deskripsi |
|------|---------|---------|-----------|
| `--da-rpc-url` | `DA_RPC_URL` | *(required)* | Celestia RPC endpoint |
| `--da-namespace` | `DA_NAMESPACE` | *(required)* | 58-char hex namespace |
| `--da-auth-token` | `DA_AUTH_TOKEN` | — | Auth token (wajib mainnet) |
| `--da-network` | `DA_NETWORK` | `mainnet` | Network: mainnet/mocha/local |
| `--da-timeout-ms` | `DA_TIMEOUT_MS` | `30000` | Operation timeout (ms) |
| `--da-retry-count` | `DA_RETRY_COUNT` | `3` | Retry count |
| `--da-retry-delay-ms` | `DA_RETRY_DELAY_MS` | `1000` | Retry delay (ms) |
| `--da-max-connections` | `DA_MAX_CONNECTIONS` | `10` | Connection pool size |
| `--da-idle-timeout-ms` | `DA_IDLE_TIMEOUT_MS` | `60000` | Idle timeout (ms) |
| `--da-enable-pooling` | `DA_ENABLE_POOLING` | `true` | Enable connection pooling |

**Development:**

| Flag | Env Var | Default | Deskripsi |
|------|---------|---------|-----------|
| `--mock-da` | `USE_MOCK_DA` | `false` | Mock DA (skip Celestia) |
| `--env-file` | `DSDN_ENV_FILE` | — | Custom env file path |

`--da-rpc-url` dan `--da-namespace` required kecuali `--mock-da` dipakai.

### `dsdn-node status`

Query status dari node yang sedang berjalan.

```bash
dsdn-node status                           # Default (127.0.0.1:45832)
dsdn-node status -p 9090                   # Custom port
dsdn-node status --host 10.0.0.5 -p 9090  # Custom host + port
```

| Flag | Default | Deskripsi |
|------|---------|-----------|
| `-p, --port` | `45832` | HTTP port of running node |
| `--host` | `127.0.0.1` | Host of running node |

### `dsdn-node health`

Query health dari node yang sedang berjalan. Flags sama dengan `status`.

```bash
dsdn-node health
dsdn-node health -p 9090
```

### `dsdn-node info`

Tampilkan build info dan konfigurasi environment.

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
NODE_HTTP_PORT:     45832
DA_RPC_URL:         http://localhost:26658
DA_NAMESPACE:       0000000000000000000000000000000000000000000064736E6474657374
DA_NETWORK:         mainnet
DA_AUTH_TOKEN:      (set)
USE_MOCK_DA:        false
═══════════════════════════════════════════════════════════════
```

### `dsdn-node version`

```bash
dsdn-node version
```

### `dsdn-node store`

Storage operations — local dan remote.

```bash
# Chunk file & store locally
dsdn-node store put <file> [--chunk-size 65536]

# Retrieve chunk from local storage
dsdn-node store get <hash> [-o output.dat]

# Check if chunk exists
dsdn-node store has <hash>

# Show storage statistics
dsdn-node store stats

# Send file chunks to remote node via gRPC
dsdn-node store send <grpc-addr> <file>

# Fetch chunk from remote node via gRPC
dsdn-node store fetch <grpc-addr> <hash> [-o output.dat]
```

**Contoh lengkap:**

```bash
# Store a local file
dsdn-node store put ./myfile.pdf --chunk-size 131072

# Check if a chunk exists
dsdn-node store has abc123def456

# Get chunk and save to file
dsdn-node store get abc123def456 -o recovered.dat

# Send to remote node
dsdn-node store send 10.0.0.5:46832 ./myfile.pdf

# Fetch from remote node
dsdn-node store fetch 10.0.0.5:46832 abc123def456 -o chunk.dat

# Storage stats
dsdn-node store stats
```

### Auto-generated Help

```bash
dsdn-node --help           # Top-level help
dsdn-node run --help       # All run flags
dsdn-node store --help     # Store subcommands
dsdn-node store put --help # Per-command help
```

## Manual Testing Guide

### Terminal 1: Start Node

```bash
# Development
cargo run --release -p dsdn-node -- run --mock-da

# Production (Celestia mocha testnet)
cargo run --release -p dsdn-node -- run \
    --da-rpc-url http://localhost:26658 \
    --da-namespace 0000000000000000000000000000000000000000000064736E6474657374 \
    --da-auth-token <TOKEN> \
    --da-network mocha
```

### Terminal 2: Test CLI Commands

```bash
# Health & status
cargo run --release -p dsdn-node -- health
cargo run --release -p dsdn-node -- status

# Store operations
cargo run --release -p dsdn-node -- store put ./README.md
cargo run --release -p dsdn-node -- store stats
cargo run --release -p dsdn-node -- store has <hash-from-put>
cargo run --release -p dsdn-node -- store get <hash> -o recovered.md
```

## Architecture Summary

### Modules

| Module | Deskripsi |
|--------|-----------|
| `cli` | Clap CLI definitions, command implementations, server setup |
| `handlers` | Axum HTTP handlers (read-only observability) |
| `da_follower` | DA subscription, event processing, source transitions |
| `event_processor` | Event handling logic dengan fallback detection |
| `placement_verifier` | Placement verification |
| `delete_handler` | Delete request handling dengan grace period |
| `state_sync` | State synchronization dengan DA |
| `health` | Health reporting dengan fallback awareness |
| `multi_da_source` | Multi-DA source abstraction (Primary/Secondary/Emergency) |
| `metrics` | Node fallback metrics untuk Prometheus export |

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

| Source | Priority | Role |
|--------|----------|------|
| Primary (Celestia) | 1 | Main DA source, selalu diutamakan |
| Secondary (Backup) | 2 | Digunakan ketika Primary gagal |
| Emergency | 3 | Last resort ketika keduanya gagal |

Transisi antar source bersifat atomic.

## HTTP Endpoints

Semua endpoint bersifat **READ-ONLY** (observability only). Node menerima command hanya via DA events, bukan via HTTP.

| Endpoint | Method | CLI Equivalent | Deskripsi |
|----------|--------|---------------|-----------|
| `/health` | GET | `dsdn-node health` | Health check (200/503) |
| `/ready` | GET | — | Readiness probe (DA connected?) |
| `/info` | GET | `dsdn-node info` | Node info (version, uptime) |
| `/status` | GET | `dsdn-node status` | Full status (state, DA, storage) |
| `/state` | GET | — | Current NodeDerivedState |
| `/state/fallback` | GET | — | Fallback state detail |
| `/state/assignments` | GET | — | Chunk assignments |
| `/da/status` | GET | — | DA layer connection status |
| `/metrics` | GET | — | Metrics JSON |
| `/metrics/prometheus` | GET | — | Prometheus text format |

**Storage Data Plane** (HTTP data-plane, bukan control plane):

| Endpoint | Method | CLI Equivalent | Deskripsi |
|----------|--------|---------------|-----------|
| `/storage/chunk/:hash` | GET | `dsdn-node store get` | Retrieve chunk |
| `/storage/chunk` | PUT | `dsdn-node store put` | Store chunk |
| `/storage/has/:hash` | GET | `dsdn-node store has` | Check chunk exists |
| `/storage/stats` | GET | `dsdn-node store stats` | Storage statistics |

### Health Criteria

| Kriteria | Kondisi |
|----------|---------|
| DA Connected | `da_connected == true` |
| No Missing Chunks | `chunks_missing == 0` |
| DA Lag | `da_behind_by < 100` |
| Storage OK | `storage_used <= storage_capacity` |

## Startup Flow

```
1. Load .env.mainnet (atau custom env file)
   └── Priority: DSDN_ENV_FILE > .env.mainnet > .env

2. Cli::parse() — clap parses flags with env fallbacks

3. Dispatch subcommand
   ├── run      → Start node server
   ├── status   → Query running node /status
   ├── health   → Query running node /health
   ├── store    → Local/remote storage operations
   ├── info     → Show config info
   └── version  → Show version

4. [run] Build NodeConfig from RunArgs
   └── Validate (production checks if mainnet)

5. [run] Initialize DA layer
   ├── --mock-da: MockDA
   └── Production: CelestiaDA + startup health check (3 retries)

6. [run] Initialize storage (LocalFsStorage)

7. [run] Start gRPC storage server (port: http + 1000)

8. [run] Start HTTP server (Axum)
   ├── Observability (/health /status /metrics ...)
   └── Storage data-plane (/storage/chunk/...)

9. [run] Start DA follower (periodic health + event loop)

10. Wait for Ctrl+C → graceful shutdown
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

## Dependencies

```toml
[dependencies]
clap = { version = "4", features = ["derive", "env"] }   # CLI framework
dotenvy = "0.15"                                          # .env file loading
reqwest = { version = "0.12", features = ["json"] }       # HTTP client (CLI queries)
serde_json = "1"                                          # JSON output
```

## Testing

```bash
cargo test -p dsdn-node                      # Unit tests
cargo test -p dsdn-node --test da_integration # Integration tests
```

### Test Categories

| Category | Deskripsi |
|----------|-----------|
| Config Validation | Empty node_id, zero port, same ports |
| Namespace Parsing | Valid hex, invalid length, invalid chars |
| Storage Backend | Put/get chunks, cache invalidation |
| DA Info Wrapper | Connection status, sequence tracking |
| Helpers | `human_bytes`, `hex_preview`, `calculate_dir_size` |

## Version History

| Version | Perubahan |
|---------|-----------|
| 14A.1A.40 | Migrasi ke clap CLI — semua config via `--flags` dengan env fallback |
| 14A.1A.30 | Storage HTTP data-plane endpoints |
| 14A.1A.20 | Multi-DA source, fallback, health monitoring |
| 14A.1A.10 | Initial node implementation |

## License

Lihat LICENSE di root repository.