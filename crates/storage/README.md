# DSDN Storage Crate

Storage layer untuk DSDN (Decentralized Storage & Data Network) dengan DA (Data Availability) awareness dan content-addressed chunk management.

## Overview

Crate `dsdn-storage` menyediakan infrastruktur penyimpanan inti untuk DSDN network — mulai dari chunking file, penyimpanan content-addressed di disk, transfer antar node via gRPC, hingga integrasi dengan DA layer untuk metadata derivation dan garbage collection.

Crate ini digunakan oleh dua binary:

- **`dsdn-node`** — storage node utama yang menjalankan gRPC server dan HTTP endpoints sebagai bagian dari node runtime
- **`dsdn-storage`** — CLI tool standalone untuk operasi storage manual dan debugging

## Arsitektur

```text
┌───────────────────────────────────────────────────────────────────────┐
│                           DSDN Node                                   │
│                                                                       │
│  ┌──────────────┐  ┌──────────────────┐  ┌─────────────────────────┐ │
│  │  DA Follower  │  │ NodeStorageBackend │  │    HTTP Server (Axum)  │ │
│  │  (events)    │  │   wraps LocalFs    │  │                        │ │
│  └──────┬───────┘  └────────┬──────────┘  │  /health /status ...   │ │
│         │                   │              │  /storage/chunk/:hash  │ │
│         │                   │              │  /storage/stats        │ │
│         ▼                   ▼              └────────────────────────┘ │
│  ┌────────────┐  ┌──────────────────┐                                │
│  │ Celestia DA │  │   gRPC Server    │◄──── dsdn-storage send         │
│  │ (metadata)  │  │  (chunk transfer)│◄──── node-to-node replication │
│  └────────────┘  └──────────────────┘                                │
│                          │                                            │
│                  ┌───────▼───────┐                                    │
│                  │  LocalFsStorage│                                   │
│                  │  (disk I/O)    │                                   │
│                  └───────┬───────┘                                    │
│                          │                                            │
│                  ┌───────▼───────┐                                    │
│                  │  objects/      │  Content-addressed storage         │
│                  │  ├── ab/       │  Path: objects/<first2>/<hash>     │
│                  │  │   └── ab... │                                    │
│                  │  └── f3/       │                                    │
│                  │      └── f3... │                                    │
│                  └───────────────┘                                    │
└───────────────────────────────────────────────────────────────────────┘
```

## Modules

| Module | File | Deskripsi |
|--------|------|-----------|
| `store` | `store.rs` | `Storage` trait abstraction — `put_chunk`, `get_chunk`, `has_chunk` |
| `localfs` | `localfs.rs` | `LocalFsStorage` — content-addressed filesystem backend dengan atomic writes |
| `chunker` | `chunker.rs` | File chunking utility — split file menjadi chunks (default 16 MiB) |
| `rpc` | `rpc.rs` | gRPC service (`DsdnStorageService`) — server & client helpers untuk chunk transfer |
| `da_storage` | `da_storage.rs` | DA-aware storage wrapper — metadata derivation dari DA events |
| `storage_proof` | `storage_proof.rs` | Proof generation untuk challenge-response verification |
| `gc` | `gc.rs` | Garbage collection berbasis DA events |
| `recovery` | `recovery.rs` | Chunk recovery dari peer nodes |
| `metrics` | `metrics.rs` | Storage health metrics dan observability |
| `events` | `events.rs` | Storage event emission untuk logging |
| `proto` | (generated) | Protobuf types — `PutRequest`, `PutResponse`, `GetRequest`, `GetResponse` |

## Storage Trait

Interface inti untuk semua storage backend:

```rust
pub trait Storage: Debug + Send + Sync + 'static {
    /// Simpan chunk data dengan hash sebagai key.
    /// Idempotent — jika hash sudah ada, tidak overwrite.
    fn put_chunk(&self, hash: &str, data: &[u8]) -> Result<()>;

    /// Ambil chunk data berdasarkan hash.
    /// Returns None jika chunk tidak ditemukan.
    fn get_chunk(&self, hash: &str) -> Result<Option<Vec<u8>>>;

    /// Cek apakah chunk dengan hash tertentu sudah tersimpan.
    fn has_chunk(&self, hash: &str) -> Result<bool>;
}
```

## LocalFsStorage

Content-addressed filesystem storage dengan fitur:

- **Atomic writes** — tulis ke temp file dulu, lalu rename (crash-safe)
- **Idempotent puts** — chunk yang sudah ada tidak di-overwrite
- **Sharded directories** — path `objects/<first2chars>/<full_hash>` untuk menghindari satu folder terlalu besar
- **Auto-create** — directory structure dibuat otomatis saat inisialisasi

```rust
use dsdn_storage::localfs::LocalFsStorage;
use dsdn_storage::store::Storage;
use dsdn_common::cid::sha256_hex;

// Inisialisasi storage di directory /data/node1
let store = LocalFsStorage::new("/data/node1")?;

// Simpan chunk
let data = b"binary chunk data...";
let hash = sha256_hex(data);
store.put_chunk(&hash, data)?;

// Ambil chunk
let retrieved = store.get_chunk(&hash)?; // Some(Vec<u8>)

// Cek keberadaan
let exists = store.has_chunk(&hash)?; // true
```

**Struktur disk:**

```
/data/node1/
└── objects/
    ├── a1/
    │   └── a1b2c3d4e5f6...  (full SHA256 hash)
    ├── f7/
    │   └── f7e8d9c0b1a2...
    └── ...
```

## Chunker

Utility untuk memecah file besar menjadi chunks yang bisa disimpan dan ditransfer secara independen.

- **Default chunk size**: 16 MiB (`DEFAULT_CHUNK_SIZE = 16 * 1024 * 1024`)
- **Streaming read**: file dibaca per-chunk, tidak di-load seluruhnya ke memori
- **Configurable size**: chunk size bisa diatur per operasi

```rust
use dsdn_storage::chunker;

// Chunk dari file path
let chunks: Vec<Vec<u8>> = chunker::chunk_file("myfile.dat", chunker::DEFAULT_CHUNK_SIZE)?;

// Chunk dari reader (apapun yang implement Read)
let mut reader = std::io::Cursor::new(data);
let chunks = chunker::chunk_reader(&mut reader, 4 * 1024 * 1024)?; // 4 MiB chunks
```

Setiap chunk di-hash dengan SHA256 (`dsdn_common::cid::sha256_hex`) sebagai content address.

## gRPC Service

Storage menyediakan gRPC server dan client untuk transfer chunk antar node.

### Protobuf Schema

```protobuf
service Storage {
    rpc Put(PutRequest)  returns (PutResponse);
    rpc Get(GetRequest)  returns (GetResponse);
}

message PutRequest  { string hash = 1; bytes data = 2; }
message PutResponse { string hash = 1; string status = 2; }
message GetRequest  { string hash = 1; }
message GetResponse { bytes data = 1; string status = 2; }
```

### Server

```rust
use dsdn_storage::rpc;
use dsdn_storage::localfs::LocalFsStorage;
use std::sync::Arc;
use tokio::sync::Notify;

let store = Arc::new(LocalFsStorage::new("./data")?);
let shutdown = Arc::new(Notify::new());
let addr = "0.0.0.0:50051".parse()?;

// Start gRPC server (blocking sampai shutdown)
rpc::run_server(addr, store, shutdown).await?;
```

### Client

```rust
use dsdn_storage::rpc;

// Kirim chunk ke node lain
let hash = rpc::client_put(
    "http://192.168.1.10:50051".to_string(),
    "abc123...".to_string(),
    chunk_data,
).await?;

// Ambil chunk dari node lain
let data = rpc::client_get(
    "http://192.168.1.10:50051".to_string(),
    "abc123...".to_string(),
).await?; // Option<Vec<u8>>
```

gRPC Put melakukan hash validation — jika client mengirim hash yang tidak cocok dengan data, server mengembalikan status `hash_mismatch`.

## Integrasi dengan Node

### NodeStorageBackend

Di `dsdn-node`, `LocalFsStorage` dibungkus dalam `NodeStorageBackend` yang implement `HealthStorage` trait untuk health reporting:

```text
NodeStorageBackend
├── local_fs: Arc<LocalFsStorage>     ← operasi chunk sebenarnya
├── objects_dir: PathBuf              ← untuk hitung disk usage
├── cached_used: RwLock<(u64, Inst)>  ← cache used bytes (30s TTL)
└── capacity_bytes: u64               ← dari NODE_STORAGE_CAPACITY_GB env
```

Health metrics dari `NodeStorageBackend` digunakan oleh semua endpoint observability node:
- `/health` — melaporkan storage issues jika disk penuh
- `/status` — `storage_used_bytes` dan `storage_capacity_bytes`
- `/metrics` — storage metrics untuk Prometheus
- `/metrics/prometheus` — `dsdn_node_storage_used_bytes` dan `dsdn_node_storage_capacity_bytes`

### Dual Server Architecture

Node menjalankan dua server secara bersamaan:

| Server | Port | Fungsi |
|--------|------|--------|
| **HTTP (Axum)** | `NODE_HTTP_PORT` (default: 8080) | Observability + storage data plane |
| **gRPC (Tonic)** | `NODE_GRPC_PORT` (default: HTTP + 1000) | Inter-node chunk transfer |

### Konfigurasi Node Storage

Semua konfigurasi via environment variables (atau `.env.mainnet`):

| Variable | Required | Default | Deskripsi |
|----------|----------|---------|-----------|
| `NODE_STORAGE_PATH` | ✅ | — | Direktori root untuk storage |
| `NODE_HTTP_PORT` | ✅ | — | Port HTTP server |
| `NODE_GRPC_PORT` | ❌ | HTTP + 1000 | Port gRPC storage server |
| `NODE_STORAGE_CAPACITY_GB` | ❌ | 100 | Kapasitas storage dalam GB (untuk reporting) |

Contoh `.env.mainnet`:

```env
NODE_ID=node-jakarta-01
NODE_STORAGE_PATH=/var/dsdn/data
NODE_HTTP_PORT=8080
NODE_GRPC_PORT=9080
NODE_STORAGE_CAPACITY_GB=500

DA_RPC_URL=http://localhost:26658
DA_NAMESPACE=0000000000000000000000000000000000000000000000000000000000
DA_AUTH_TOKEN=eyJhbGciOi...
DA_NETWORK=mainnet
```

## CLI Reference

### dsdn-storage (Standalone)

Binary standalone untuk operasi storage tanpa menjalankan full node.

**Semua operasi lokal menggunakan `./data` sebagai storage directory.**

#### Server Mode

Jalankan gRPC storage server standalone:

```bash
dsdn-storage server 127.0.0.1:50051
```

Output:
```
🚀 Starting DSDN Storage gRPC server at 127.0.0.1:50051
Press Ctrl+C to stop.
```

#### Put (lokal)

Chunk file dan simpan ke storage lokal:

```bash
# Default chunk size (16 MiB)
dsdn-storage put myfile.dat

# Custom chunk size (4 MiB)
dsdn-storage put myfile.dat 4194304
```

Output:
```
📦 Uploading 3 chunks (chunk_size = 16777216)
  chunk    0: a1b2c3d4e5f6... (16777216 bytes)
  chunk    1: f7e8d9c0b1a2... (16777216 bytes)
  chunk    2: 9876543210ab... (1234567 bytes)
✅ Done storing locally in ./data
```

#### Get (lokal)

Ambil chunk dari storage lokal:

```bash
# Tampilkan info chunk
dsdn-storage get a1b2c3d4e5f6...

# Simpan ke file
dsdn-storage get a1b2c3d4e5f6... output.bin
```

#### Has (lokal)

Cek apakah chunk ada di storage lokal:

```bash
dsdn-storage has a1b2c3d4e5f6...
# ✅ Chunk exists: a1b2c3d4e5f6...
```

#### Send (remote)

Kirim file ke remote gRPC server:

```bash
dsdn-storage send 192.168.1.10:50051 myfile.dat
```

Output:
```
📤 Sending 3 chunks to 192.168.1.10:50051
  chunk    0: sent → a1b2c3d4e5f6...
  chunk    1: sent → f7e8d9c0b1a2...
  chunk    2: sent → 9876543210ab...
✅ File transfer done.
```

#### Fetch (remote)

Ambil chunk dari remote gRPC server:

```bash
# Tampilkan info
dsdn-storage fetch 192.168.1.10:50051 a1b2c3d4e5f6...

# Simpan ke file
dsdn-storage fetch 192.168.1.10:50051 a1b2c3d4e5f6... output.bin
```

### dsdn-node store (Node CLI)

Subcommand `store` di binary `dsdn-node` — menggunakan `NODE_STORAGE_PATH` dari environment.

#### Put

```bash
# Default chunk size
dsdn-node store put myfile.dat

# Custom chunk size
dsdn-node store put myfile.dat 4194304
```

#### Get

```bash
# Info chunk
dsdn-node store get a1b2c3d4e5f6...

# Simpan ke file
dsdn-node store get a1b2c3d4e5f6... output.bin
```

#### Has

```bash
dsdn-node store has a1b2c3d4e5f6...
```

#### Stats

Tampilkan statistik storage:

```bash
dsdn-node store stats
```

Output:
```
═══════════════════════════════════════════════════════════════
                  DSDN Storage Statistics
═══════════════════════════════════════════════════════════════
Storage path:   /var/dsdn/data
Objects dir:    /var/dsdn/data/objects
Total chunks:   1,247
Total size:     18.72 GiB (20100200448 bytes)
═══════════════════════════════════════════════════════════════
```

#### Send

```bash
dsdn-node store send 192.168.1.10:9080 myfile.dat
```

#### Fetch

```bash
dsdn-node store fetch 192.168.1.10:9080 a1b2c3d4e5f6... output.bin
```

### Perbedaan dsdn-storage vs dsdn-node store

| Aspek | `dsdn-storage` | `dsdn-node store` |
|-------|---------------|-------------------|
| Storage path | Hardcoded `./data` | Dari `NODE_STORAGE_PATH` env |
| Dependency | Standalone, hanya butuh `dsdn-storage` | Butuh full node dependencies |
| Gunakan untuk | Development, debugging, testing | Operasi pada node yang sudah deploy |
| gRPC server | Mode `server` terpisah | Otomatis jalan saat `dsdn-node run` |

## HTTP Storage Endpoints

Saat `dsdn-node run`, node menyediakan storage endpoints di HTTP server yang sama dengan observability endpoints.

**Penting:** Endpoints ini adalah *data plane* operations — bukan control plane. Control plane commands tetap datang via DA events.

### GET /storage/chunk/{hash}

Ambil raw chunk data berdasarkan hash.

```bash
curl http://localhost:8080/storage/chunk/a1b2c3d4e5f6...
# → binary chunk data (application/octet-stream)
```

Response codes:
- `200` — chunk ditemukan, body berisi raw bytes
- `404` — chunk tidak ada
- `500` — storage error

### PUT /storage/chunk

Simpan chunk. Hash dihitung otomatis dari body data.

```bash
curl -X PUT \
  http://localhost:8080/storage/chunk \
  --data-binary @myfile.chunk0
```

Response (`200`):
```json
{
  "hash": "a1b2c3d4e5f6...",
  "size": 16777216,
  "status": "ok"
}
```

Response codes:
- `200` — chunk berhasil disimpan
- `400` — body kosong
- `500` — storage error

### GET /storage/has/{hash}

Cek apakah chunk ada.

```bash
curl http://localhost:8080/storage/has/a1b2c3d4e5f6...
```

Response (`200`):
```json
{
  "hash": "a1b2c3d4e5f6...",
  "exists": true
}
```

### GET /storage/stats

Statistik storage.

```bash
curl http://localhost:8080/storage/stats
```

Response (`200`):
```json
{
  "total_chunks": 1247,
  "total_bytes": 20100200448,
  "storage_path": "/var/dsdn/data"
}
```

## gRPC Storage Endpoints

Port default: `NODE_HTTP_PORT + 1000` (atau `NODE_GRPC_PORT` jika di-set manual).

### Put

Kirim chunk ke node. Server memvalidasi hash jika disediakan.

```
rpc Put(PutRequest) returns (PutResponse)
```

- Jika `hash` kosong → server hitung hash sendiri
- Jika `hash` diisi → server validasi apakah `sha256(data) == hash`
- Jika mismatch → response status `hash_mismatch: expected X, got Y`

### Get

Ambil chunk dari node.

```
rpc Get(GetRequest) returns (GetResponse)
```

- `NOT_FOUND` jika chunk tidak ada
- `INTERNAL` jika storage error

### Contoh Penggunaan gRPC dari Rust

```rust
use dsdn_storage::rpc;

// Kirim chunk
let hash = rpc::client_put(
    "http://192.168.1.10:9080".to_string(),
    hash_string,
    data_bytes,
).await?;

// Ambil chunk
let data = rpc::client_get(
    "http://192.168.1.10:9080".to_string(),
    hash_string,
).await?;
```

## DA Awareness

**Storage BUKAN sumber kebenaran.** Semua metadata berasal dari DA layer.

### Prinsip Fundamental

1. **Metadata derived from DA** — semua chunk metadata (assignment, replicas, commitments) diturunkan dari DA events
2. **State reconstructable** — state storage dapat direkonstruksi sepenuhnya dari DA
3. **No local authority** — storage lokal tidak membuat keputusan tanpa dasar DA
4. **Idempotent operations** — put_chunk dengan hash yang sama adalah no-op

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

### DAStorage Wrapper

```rust
use dsdn_storage::{DAStorage, StorageMetrics};
use dsdn_storage::localfs::LocalFsStorage;
use dsdn_common::MockDA;
use std::sync::Arc;

let inner = Arc::new(LocalFsStorage::new("/path/to/storage")?);
let da = Arc::new(MockDA::new());
let storage = DAStorage::new(inner, da);

// Receive DA events
storage.receive_chunk_declared(event);
storage.sync_metadata_from_da()?;

// Store chunk (verified against DA commitment)
storage.put_chunk_with_meta(hash, data, commitment)?;

// Get metrics
let metrics = StorageMetrics::collect(&storage);
```

## Lifecycle Chunk

### 1. Declare

Chunk dideklarasikan di DA layer dengan metadata: hash, size, commitment (SHA3-256), target replication factor.

### 2. Store

Data chunk disimpan di storage lokal. Commitment diverifikasi, metadata di-sync dari DA. Put bersifat idempotent — jika chunk sudah ada, tidak di-overwrite.

### 3. Verify

Commitment verification: `SHA3-256(data) == da_commitment`. Challenge-response proof generation via `storage_proof` module.

### 4. Replicate

Replica assignment dari DA via `ReplicaAdded` events. Chunk ditransfer via gRPC ke node target. `current_rf` tracking untuk memastikan replication factor tercapai.

### 5. Delete

Delete request dari DA via `DeleteRequested` event. Grace period sebelum actual deletion.

### 6. Garbage Collection

GC berbasis DA events — hanya menghapus chunks yang eligible:

- **Deleted**: `DeleteRequested` + grace period expired
- **Orphaned**: Tidak di-assign ke node ini
- **Corrupted**: Commitment mismatch

```text
scan() ──► GCScanResult ──► collect() ──► Deleted chunks
```

## Recovery

### Recovery Process

1. Identify missing chunks (assigned via DA tapi tidak di storage lokal)
2. Fetch dari peer nodes via gRPC (`client_get`)
3. Verify commitment sebelum store
4. Tidak overwrite existing chunks (idempotent)

### Safety Guarantees

- Recovery **hanya** untuk chunks yang assigned via DA
- Data **wajib** diverifikasi sebelum disimpan
- **No overwrite** untuk existing chunks
- Recovery berbasis DA assignment, bukan heuristik

## Invariants

Crate ini menjamin invariant berikut:

1. **Metadata Derivation** — semua chunk metadata dapat direkonstruksi dari DA events
2. **No Unauthorized Storage** — tidak ada chunk disimpan tanpa dasar DA (kecuali manual via CLI/HTTP)
3. **Commitment Integrity** — setiap chunk yang disimpan memiliki commitment yang valid
4. **Atomic Writes** — penulisan ke disk menggunakan write-then-rename (crash-safe)
5. **Idempotent Puts** — `put_chunk` dengan hash yang sudah ada adalah no-op
6. **Content Addressing** — path di disk ditentukan oleh hash: `objects/<first2>/<hash>`
7. **Hash Validation** — gRPC server memvalidasi hash terhadap data yang diterima
8. **Recovery Safety** — recovery hanya untuk assigned chunks dengan verifikasi
9. **GC Safety** — GC hanya menghapus chunks yang eligible via DA events
10. **Event Isolation** — events tidak mempengaruhi correctness storage

## Quick Start

### Development (Mock DA)

```bash
# Setup
echo 'USE_MOCK_DA=true' >> .env
echo 'NODE_ID=dev-node-1' >> .env
echo 'NODE_STORAGE_PATH=./data' >> .env
echo 'NODE_HTTP_PORT=8080' >> .env

# Start node (includes storage gRPC on port 9080)
cargo run --bin dsdn-node -- run

# Di terminal lain — store file
cargo run --bin dsdn-node -- store put testfile.dat

# Cek stats
cargo run --bin dsdn-node -- store stats

# Ambil chunk via HTTP
curl http://localhost:8080/storage/has/abc123...
curl http://localhost:8080/storage/chunk/abc123... -o chunk.bin

# Transfer ke node lain via gRPC
cargo run --bin dsdn-node -- store send 127.0.0.1:9080 testfile.dat
```

### Production (Mainnet)

```bash
# Setup .env.mainnet
cat > .env.mainnet << EOF
NODE_ID=node-jakarta-01
NODE_STORAGE_PATH=/var/dsdn/data
NODE_HTTP_PORT=8080
NODE_GRPC_PORT=9080
NODE_STORAGE_CAPACITY_GB=500
DA_RPC_URL=http://localhost:26658
DA_NAMESPACE=0000000000000000000000000000000000000000000000000000000000
DA_AUTH_TOKEN=eyJhbGciOi...
DA_NETWORK=mainnet
EOF

# Start node
cargo run --release --bin dsdn-node -- run

# Monitor storage
curl http://localhost:8080/storage/stats
curl http://localhost:8080/status
curl http://localhost:8080/metrics/prometheus | grep storage
```

### Standalone Storage Server

Untuk testing atau deploy storage terpisah tanpa full node:

```bash
# Jalankan gRPC server standalone
cargo run --bin dsdn-storage -- server 0.0.0.0:50051

# Di terminal lain — kirim file
cargo run --bin dsdn-storage -- put myfile.dat
cargo run --bin dsdn-storage -- send 127.0.0.1:50051 myfile.dat

# Fetch dari remote
cargo run --bin dsdn-storage -- fetch 127.0.0.1:50051 abc123... output.bin
```

## Endpoint Summary

### HTTP Endpoints (Node)

| Method | Path | Deskripsi |
|--------|------|-----------|
| `GET` | `/storage/chunk/{hash}` | Ambil chunk data (raw bytes) |
| `PUT` | `/storage/chunk` | Simpan chunk (hash auto-computed) |
| `GET` | `/storage/has/{hash}` | Cek chunk ada atau tidak |
| `GET` | `/storage/stats` | Statistik storage (total chunks, bytes) |
| `GET` | `/status` | Node status (termasuk `storage_used_bytes`, `storage_capacity_bytes`) |
| `GET` | `/metrics` | JSON metrics (termasuk storage) |
| `GET` | `/metrics/prometheus` | Prometheus format (`dsdn_node_storage_*`) |

### gRPC Endpoints (Node & Standalone)

| RPC | Request | Response | Deskripsi |
|-----|---------|----------|-----------|
| `Put` | `PutRequest { hash, data }` | `PutResponse { hash, status }` | Simpan chunk dengan validasi hash |
| `Get` | `GetRequest { hash }` | `GetResponse { data, status }` | Ambil chunk |

### CLI Commands

| Command | Binary | Deskripsi |
|---------|--------|-----------|
| `store put <file> [size]` | `dsdn-node` | Chunk file & simpan lokal |
| `store get <hash> [out]` | `dsdn-node` | Ambil chunk dari lokal |
| `store has <hash>` | `dsdn-node` | Cek chunk ada |
| `store stats` | `dsdn-node` | Statistik storage |
| `store send <addr> <file>` | `dsdn-node` | Kirim file via gRPC |
| `store fetch <addr> <hash> [out]` | `dsdn-node` | Fetch chunk dari remote |
| `server <addr>` | `dsdn-storage` | Jalankan gRPC server standalone |
| `put <file> [size]` | `dsdn-storage` | Chunk file & simpan ke `./data` |
| `get <hash> [out]` | `dsdn-storage` | Ambil chunk dari `./data` |
| `has <hash>` | `dsdn-storage` | Cek chunk di `./data` |
| `send <addr> <file>` | `dsdn-storage` | Kirim file ke remote gRPC |
| `fetch <addr> <hash> [out]` | `dsdn-storage` | Fetch chunk dari remote gRPC |

## Testing

```bash
# Unit tests
cargo test --package dsdn-storage

# Integration tests (DA integration)
cargo test --package dsdn-storage --test da_integration

# Test specific module
cargo test --package dsdn-storage -- localfs
cargo test --package dsdn-storage -- chunker
cargo test --package dsdn-storage -- rpc
```

Tests yang tersedia:

- **localfs** — put/get/has, atomic write idempotency, chunking + store integration
- **chunker** — small files, exact multiples, streaming
- **rpc** — hash validation, mismatch detection, client helpers
- **da_integration** — DA → metadata derivation, recovery roundtrip, GC safety, metrics consistency, event emission

## Version

Tahap: 14A