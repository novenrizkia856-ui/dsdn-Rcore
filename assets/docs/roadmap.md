# DSDN Roadmap

**Nama Proyek:** DSDN (Distributed Storage and Data Network)  
**Periode Target:** 2025 -- 2030

---

## Tahap 0 --- Prasyarat Environment

**Tujuan:** Menyiapkan alat dasar untuk coding sistem DSDN.

**Langkah:**

1. Instal Rust toolchain terbaru (edition 2021).
2. Pastikan `cargo` dan `rustup` sudah terinstal.
3. Tambahkan target `wasm32-wasi` agar bisa compile program WASM.
4. Jalankan perintah berikut di terminal (boleh di-skip jika sudah pernah diinstal):

```bash
rustup toolchain install stable
rustup default stable
rustup target add wasm32-wasi
```

5. Pastikan bisa menjalankan perintah:

```bash
cargo --version
rustc --version
```

6. Tes dengan membuat proyek uji sederhana:

```bash
cargo new hello
cd hello
cargo build
```

**Selesai jika:** Build sukses tanpa error.

---

## Tahap 1 --- Struktur Awal Workspace

**Tujuan:** Membuat seluruh folder dan file dasar DSDN.

**Langkah:**

1. Buat folder utama bernama `dsdn`.
2. Di dalam `dsdn`, buat file `Cargo.toml` untuk workspace.
3. Buat folder bernama `crates`.
4. Di dalam `crates`, buat subfolder berikut: `common`, `proto`, `storage`, `coordinator`, `node`, `validator`, `runtime_wasm`, `runtime_vm`, `ingress`, `agent`, `chain`.
5. Tiap subfolder berisi: `Cargo.toml`, `src/`, file utama (`lib.rs` atau `main.rs` sesuai tipe crate).
6. Buat juga folder `tools` di luar `crates`.

**Struktur akhir:**

```
dsdn/
├── Cargo.toml
├── crates/
│   ├── common/
│   ├── proto/
│   ├── storage/
│   ├── coordinator/
│   ├── node/
│   ├── validator/
│   ├── runtime_wasm/
│   ├── runtime_vm/
│   ├── ingress/
│   ├── agent/
│   └── chain/
└── tools/
```

7. Isi setiap file hanya dengan komentar `TODO` agar build tidak gagal.
8. Jalankan `cargo build` di root.

**Selesai jika:** Seluruh crate bisa di-build.

---

## Tahap 2 --- Common Primitives

**Tujuan:** Membuat tipe dan fungsi dasar yang dipakai semua modul.

**Langkah:**

1. Tambahkan modul `crypto` untuk Ed25519 (buat keypair, sign, verify).
2. Tambahkan modul `cid` untuk hashing sha256 yang menghasilkan content ID.
3. Tambahkan modul `config` untuk parsing file konfigurasi dengan serde.
4. Buat hasilnya di crate `common`.
5. Uji fungsi hash agar hasil selalu sama untuk input sama.
6. Uji sign dan verify agar sukses.

**Selesai jika:** Semua tes di crate `common` lulus.

---

## Tahap 3 --- Storage Dasar

**Tujuan:** Membuat sistem penyimpanan lokal berbasis chunk.

**Langkah:**

1. Buat modul `chunker` untuk memotong file menjadi potongan 16 hingga 64 MiB.
2. Setiap chunk di-hash menggunakan `common::cid`.
3. Buat trait `Storage` dengan fungsi `put_chunk`, `get_chunk`, dan `has_chunk`.
4. Implementasikan backend `localfs` yang menyimpan data di folder `objects/hash`.
5. Buat command line sederhana: `storage-cli put <file>` yang menampilkan daftar hash.
6. Uji dengan menulis dan membaca ulang chunk yang sama.

**Selesai jika:** `put`/`get` berjalan dan data tersimpan di disk.

---

## Tahap 4 --- Storage RPC

**Tujuan:** Membuat server RPC untuk mengirim dan menerima chunk antar node.

**Langkah:**

1. Gunakan `tonic` (gRPC) untuk implementasi komunikasi.
2. Gunakan file proto di crate `proto` untuk pesan `PutRequest` dan `GetRequest`.
3. Implementasikan server gRPC di crate `storage`.
4. Implementasikan client sederhana untuk mengirim data ke server lain.
5. Jalankan node lokal dan tes kirim chunk dari client ke server.

**Selesai jika:** RPC berjalan dan data tersimpan di node penerima.

---

## Tahap 5 --- Coordinator

**Tujuan:** Membuat pusat metadata dan pendaftaran node.

**Langkah:**

1. Implementasikan penyimpanan metadata di memori untuk awal.
2. Tambahkan API untuk:
   - Register node (id, zona, kapasitas).
   - Query placement berdasarkan hash.
   - Update status replika.
3. Tambahkan algoritma consistent hashing sederhana untuk pemilihan node.
4. Uji dengan 5 node di 3 zona, cek hasil replikasi maksimal 3 zona berbeda.

**Selesai jika:** Coordinator bisa menampilkan daftar node untuk hash tertentu.

---

## Tahap 6 --- Self Healing dan Replikasi

**Tujuan:** Membuat sistem replikasi otomatis jika ada replika kurang.

**Langkah:**

1. Node menjalankan tugas latar untuk memeriksa chunk yang hilang.
2. Jika chunk belum ada, node mengambil dari node lain.
3. Coordinator melacak replika dan menugaskan node baru jika perlu.
4. Uji dengan upload file ke satu node lalu tunggu hingga 3 node punya salinan.

**Selesai jika:** Replikasi otomatis tercapai.

---

## Tahap 7 --- Runtime WASM

**Tujuan:** Menjalankan program WASM dalam sandbox aman.

**Langkah:**

1. Gunakan crate `wasmtime` untuk eksekusi WASM.
2. Buat fungsi `run_wasm(module_bytes, input)` yang mengembalikan output.
3. Batasi waktu dan memori.
4. Uji dengan module sederhana yang mengembalikan string `"hello"`.

**Selesai jika:** WASM bisa dijalankan dan menghasilkan output.

---

## Tahap 8 --- Runtime MicroVM

**Tujuan:** Membuat interface eksekusi Python atau native di microVM.

**Langkah:**

1. Buat trait `MicroVM` dengan fungsi `start`, `stop`, `exec`.
2. Implementasikan `MockVM` sebagai subprocess biasa.
3. Uji dengan menjalankan command kecil seperti `echo hello`.

**Selesai jika:** VM mock berfungsi.

---

## Tahap 9 --- Scheduler dan Skor Node

**Tujuan:** Memilih node terbaik untuk menjalankan workload.

**Langkah:**

1. Gunakan rumus:

```
S = w1*CPU_free + w2*RAM_free + w3*GPU_free + w4*(1/latensi) - w5*IO_pressure
```

2. Buat fungsi `schedule(workload) -> node_id`.
3. Uji dengan data dummy dan pastikan hasilnya logis.

**Selesai jika:** Node terbaik terpilih sesuai skor.

---

## Tahap 10 --- Validator

**Tujuan:** Menegakkan kebijakan aplikasi publik tanpa membaca data privat.

**Langkah:**

1. Validator memeriksa manifest aplikasi dan tanda tangan.
2. Tambahkan daftar hash terlarang untuk blokir.
3. Tambahkan log audit.
4. Uji dengan manifest normal dan manifest berisi hash terlarang.

**Selesai jika:** Validasi berfungsi.

---

## Tahap 11 --- Ingress HTTP

**Tujuan:** Melayani pengguna akhir melalui HTTP.

**Langkah:**

1. Gunakan `axum` atau `hyper` untuk web server.
2. Route `/object/{hash}` menuju node terdekat dari coordinator.
3. Buat endpoint `/health` untuk pengecekan status.
4. Uji dengan meminta objek melalui ingress dan pastikan data diterima.

**Selesai jika:** HTTP gateway berfungsi.

---

## Tahap 12 --- Agent

**Tujuan:** Membuat client CLI untuk upload dan download data.

**Langkah:**

1. Implementasikan perintah `upload` dan `get`.
2. Tambahkan opsi enkripsi AES-GCM di sisi klien.
3. Implementasikan Shamir Secret Sharing untuk recovery kunci.
4. Uji upload terenkripsi dan pastikan bisa didekripsi kembali.

**Selesai jika:** File terenkripsi berhasil dikirim dan diambil.

---

## Tahap 13 --- Chain Nusantara

Seluruh core blockchain sebagaimana didefinisikan dalam whitepaper.

---

## Catatan Penting: Tahap 14--30

> Seluruh tahap pada rentang ini bersifat **internal infrastructure hardening**. Penyelesaian teknis pada tahap ini **tidak menandakan** kesiapan produk publik, tidak boleh dijadikan dasar marketing, klaim adopsi, atau ekspektasi pengguna. Semua modul yang selesai di fase ini dianggap **engine internal**, bukan fitur yang diekspos ke publik.

---

## Tahap 14A --- Celestia DA Mirror dan State Reconstruction (Read-Only Mode)

**Tujuan:** Memastikan seluruh metadata DSDN dapat direkonstruksi secara deterministik dari Celestia DA, tanpa ketergantungan metadata lokal, tanpa melibatkan ekonomi, reward, atau slashing. Tahap ini murni validasi data-plane dan control-plane.

**Prinsip Penting:**

- Celestia DA = single source of truth.
- Coordinator dan node tidak boleh menyimpan metadata authoritative.
- Local state hanya hasil replay blob DA.
- Tidak ada reward, receipt, stake enforcement.

**Perubahan Arsitektur:**

Semua event metadata (`node_register`, `chunk_placement`, `replica_update`, `delete_request`) harus di-post ke Celestia DA sebagai blob. Local metadata cache hanya boleh bersifat derived, ephemeral, dan rebuildable.

**Arsitektur DA Abstraction:**

```rust
trait DALayer {
    fn post_blob(data: &[u8]) -> Result<BlobRef>;
    fn get_blob(ref: BlobRef) -> Result<Vec<u8>>;
    fn subscribe_blobs(namespace: &str) -> Stream<Blob>;
    fn health_check() -> DAHealthStatus;
}
```

Tahap ini juga bertujuan membuktikan bahwa seluruh komponen sistem termasuk coordinator tidak memerlukan kepercayaan implisit, karena setiap state dapat direkonstruksi ulang oleh pihak independen hanya dari Data Availability log.

### Langkah Implementasi

#### 1. DA Event Schema

Buat enum `DAEvent` di crate `proto`: `NodeRegistered`, `ChunkDeclared`, `ReplicaAdded`, `ReplicaRemoved`, `DeleteRequested`.

Semua event harus bersifat: deterministic, ordered, versioned.

#### 2. Coordinator --- DA Consumer

Coordinator: subscribe Celestia light node, replay blob dari genesis / checkpoint, build state via log-sink state machine. State lokal meliputi: `node_registry`, `chunk_map`, `replica_map`, `zone_map`.

#### 3. Node --- DA Follower

Node: pull blob Celestia, apply event secara berurutan. Node tidak boleh menerima instruksi dari coordinator via RPC. Coordinator hanya publish event, node mengikuti.

#### 3.1 DA Abstraction Layer

- Buat trait `DALayer` di crate `common`.
- Implementasi `CelestiaDA` sebagai primary.
- Placeholder untuk `FallbackDA` (diimplementasi di 14A.1).

#### 4. dev-run.sh

Script menjalankan: Celestia light node (dummy/local), Coordinator (DA consumer), 2 node reguler, 1 node data center, Ingress, Agent CLI.

### Validasi Wajib

- Restart coordinator --- state identik.
- Restart node --- state identik.
- Delay / reorder blob --- state tetap konsisten.
- Tidak ada metadata lokal yang diperlukan untuk recovery.

### Kriteria Selesai

- Semua node dan coordinator 100% hidup dari DA replay.
- Tidak ada metadata authoritative lokal.
- Sistem tetap berfungsi tanpa chain dan ekonomi.

**Crates terlibat:** `coordinator`, `node`, `proto`, `common`, `ingress`, `agent`, `storage`.

> Tahap ini strictly read-only, dan dilarang menjadi dependensi UX, API publik, atau klaim desentralisasi ke pengguna.

---

## Tahap 14A.A1 --- Celestia Mainnet Integration

**Crates:** `common`, `coordinator`, `node`

### Tujuan

Mengintegrasikan DSDN dengan Celestia Mainnet sebagai production DA layer.

Tahap ini membuktikan bahwa:

- `CelestiaDA` implementation berfungsi dengan network asli.
- Coordinator dapat rebuild state dari Celestia mainnet.
- Node dapat follow events dari Celestia mainnet.
- System handle real-world network conditions.

Setelah tahap ini, DSDN siap production dengan DA layer asli.

### Prerequisites

1. Celestia light node running dan synced ke mainnet.
2. Wallet dengan TIA tokens untuk blob fees.
3. Auth token dari celestia light node.
4. Semua tahap 14A.1 -- 14A.40 selesai.

### Ruang Lingkup dan Perubahan

#### A. Celestia Light Node Setup (Dokumentasi)

**Installation Guide:**

- Install `celestia-node` binary.
- Initialize light node untuk mainnet.
- Start dan sync light node.
- Generate auth token.

**Hardware Requirements:**

- CPU: 2+ cores
- RAM: 4+ GB
- Storage: 50+ GB SSD
- Network: Stable internet connection

**Commands Reference:**

```bash
# Install
curl -sL https://get.celestia.org | bash

# Initialize mainnet light node
celestia light init --p2p.network celestia

# Start light node
celestia light start --core.ip <consensus-endpoint> --p2p.network celestia

# Get auth token
celestia light auth admin --p2p.network celestia
```

#### B. Environment Configuration

Environment variables untuk production:

```env
# Celestia Mainnet Configuration
DA_RPC_URL=http://localhost:26658
DA_AUTH_TOKEN=<your-auth-token>
DA_NAMESPACE=<58-hex-chars-dsdn-namespace>
DA_TIMEOUT_MS=30000
DA_RETRY_COUNT=3
DA_RETRY_DELAY_MS=1000
```

#### C. Crate Changes

**Crate: `common`**

File: `crates/common/src/celestia_da.rs`

Perubahan:

1. Tambah auth token header untuk authenticated requests.
2. Improve error handling untuk network errors.
3. Add connection pooling untuk performance.
4. Add metrics untuk latency tracking.

File: `crates/common/src/da.rs`

Perubahan:

1. `DAConfig` tambah field untuk mainnet-specific settings.
2. Add `DAMetrics` struct untuk observability.

**Crate: `coordinator`**

File: `crates/coordinator/src/main.rs`

Perubahan:

1. Load `DAConfig` dari environment.
2. Initialize `CelestiaDA` dengan auth token.
3. Add startup validation (test connection sebelum serve).
4. Add graceful degradation jika DA temporarily unavailable.

File: `crates/coordinator/src/da_consumer.rs`

Perubahan:

1. Add reconnection logic untuk network interruptions.
2. Add blob verification (commitment check).
3. Add metrics untuk blob processing.

**Crate: `node`**

File: `crates/node/src/main.rs`

Perubahan:

1. Load `DAConfig` dari environment (bukan CLI untuk production).
2. Support both CLI args dan env vars.
3. Add startup DA health check.
4. Improve error messages untuk connection failures.

#### D. Integration Tests (Mainnet)

File: `crates/common/tests/celestia_mainnet_integration.rs`

Tests (require running light node):

1. `test_mainnet_post_blob` --- Post small blob ke mainnet, verify `BlobRef` returned.
2. `test_mainnet_get_blob` --- Post blob, then retrieve, verify data integrity.
3. `test_mainnet_roundtrip_latency` --- Measure post-to-get latency, assert < 30 seconds.
4. `test_mainnet_subscribe_blobs` --- Subscribe to namespace, post blob, verify received via subscription.
5. `test_mainnet_health_check` --- Verify `health_check` returns Healthy, test with real node.
6. `test_mainnet_reconnection` --- Simulate connection drop, verify auto-reconnect.

#### E. Production Scripts

File: `scripts/run-mainnet.sh`

```bash
#!/bin/bash
# DSDN Mainnet Runner
# Prerequisites: Celestia light node running

set -e

# Check prerequisites
if ! curl -s http://localhost:26658 > /dev/null; then
    echo "ERROR: Celestia light node not running"
    echo "Start with: celestia light start --p2p.network celestia"
    exit 1
fi

# Load environment
source .env.mainnet

# Start coordinator
echo "Starting coordinator..."
cargo run -p dsdn-coordinator --release &
COORDINATOR_PID=$!

sleep 5

# Start nodes
echo "Starting nodes..."
cargo run -p dsdn-node --bin dsdn-node --release -- \
    node-1 "$DA_RPC_URL" ./data/node1 8081 &
NODE1_PID=$!

cargo run -p dsdn-node --bin dsdn-node --release -- \
    node-2 "$DA_RPC_URL" ./data/node2 8082 &
NODE2_PID=$!

echo "DSDN Mainnet running"
echo "Coordinator PID: $COORDINATOR_PID"
echo "Node 1 PID: $NODE1_PID"
echo "Node 2 PID: $NODE2_PID"

# Wait for interrupt
trap "kill $COORDINATOR_PID $NODE1_PID $NODE2_PID 2>/dev/null" EXIT
wait
```

File: `.env.mainnet.example`

```env
# Celestia Mainnet Configuration
DA_RPC_URL=http://localhost:26658
DA_AUTH_TOKEN=your_auth_token_here
DA_NAMESPACE=0102030405060708091011121314151617181920212223242526272829
DA_TIMEOUT_MS=30000
DA_RETRY_COUNT=3
DA_RETRY_DELAY_MS=1000

# Node Configuration
RUST_LOG=info
```

#### F. Documentation

File: `docs/CELESTIA_MAINNET_SETUP.md`

Contents: Prerequisites, Celestia Light Node Setup, TIA Token Acquisition, DSDN Configuration, Running DSDN with Mainnet, Troubleshooting, Cost Estimation.

File: `docs/MAINNET_OPERATIONS.md`

Contents: Monitoring DA Health, Handling DA Outages, Namespace Management, Blob Fee Optimization, Backup and Recovery.

#### G. CLI Update (node crate)

Updated CLI untuk support environment variables:

```bash
# Option 1: CLI arguments (development)
cargo run -p dsdn-node --bin dsdn-node -- node-1 mock ./data/node1 8080

# Option 2: Environment variables (production)
export DA_RPC_URL=http://localhost:26658
export DA_AUTH_TOKEN=xxx
export DA_NAMESPACE=xxx
cargo run -p dsdn-node --bin dsdn-node -- node-1 env ./data/node1 8080

# "env" keyword = load DA config from environment
```

### Validasi Wajib

**Blob Operations:**

- `post_blob` ke mainnet berhasil.
- `get_blob` dari mainnet berhasil.
- `subscribe_blobs` receive real-time.
- Roundtrip latency < 30 detik.

**Coordinator:**

- Start dengan mainnet DA.
- Rebuild state dari mainnet blobs.
- Publish events ke mainnet.
- Handle temporary DA unavailability.

**Node:**

- Start dengan mainnet DA.
- Follow events dari mainnet.
- Health endpoint reflect DA status.
- Reconnect after network interruption.

**End-to-End:**

- Coordinator publish --- Node receive.
- System survive 5-minute DA latency spike.
- Restart coordinator --- state identical.
- Restart node --- state identical.

**Operations:**

- Monitoring dashboard shows DA metrics.
- Alerting untuk DA degradation.
- Documentation complete.

### Cost Estimation

Celestia Mainnet Blob Fees (approximate):

- Small blob (< 1 KB): ~0.0001 TIA (~$0.0001)
- Medium blob (10 KB): ~0.001 TIA (~$0.001)
- Large blob (100 KB): ~0.01 TIA (~$0.01)

Estimated monthly cost untuk development:

- 1000 blobs/day x 30 days = 30,000 blobs
- Average 10 KB per blob
- Cost: ~30 TIA (~$27/month)

### Aturan Keras

**Dilarang:**

- Hardcode auth token di source code.
- Commit `.env` files dengan credentials.
- Skip connection validation saat startup.
- Ignore DA errors silently.
- Deploy tanpa monitoring.

**Wajib:**

- Auth token dari environment variable.
- Connection test sebelum serve traffic.
- Graceful handling untuk DA unavailability.
- Metrics untuk observability.
- Documentation untuk operators.

### Files Summary

**Baru:**

- `crates/common/tests/celestia_mainnet_integration.rs`
- `scripts/run-mainnet.sh`
- `.env.mainnet.example`
- `docs/CELESTIA_MAINNET_SETUP.md`
- `docs/MAINNET_OPERATIONS.md`

**Diubah:**

- `crates/common/src/celestia_da.rs` (auth token, metrics)
- `crates/common/src/da.rs` (DAConfig, DAMetrics)
- `crates/coordinator/src/main.rs` (env config, validation)
- `crates/coordinator/src/da_consumer.rs` (reconnection, verification)
- `crates/node/src/main.rs` (env support, health check)

### Deliverables

1. Working integration dengan Celestia mainnet.
2. Production-ready scripts.
3. Complete documentation.
4. Integration tests (skippable tanpa light node).
5. Monitoring dan metrics infrastructure.

### Kriteria Selesai

- Coordinator + Nodes running dengan Celestia mainnet.
- Event flow: Coordinator --- DA --- Node working.
- State reconstruction dari mainnet blobs verified.
- System handle real network conditions.
- Documentation complete untuk operators.
- Cost tracking implemented.

> Tahap ini membuktikan bahwa DSDN production-ready dengan real DA layer. Setelah tahap ini, DA layer bukan lagi mock --- sistem berjalan dengan Data Availability asli dari Celestia mainnet.

---

## Tahap 14A.1A --- DA Fallback Layer (Celestia Resilience)

**Tujuan:** Menghilangkan single point of failure pada Celestia DA dengan implementasi fallback layer yang dapat diaktifkan secara otomatis atau manual.

**Prinsip Penting:**

- Celestia tetap primary DA.
- Fallback hanya aktif saat Celestia degraded.
- State harus identical regardless of DA source.
- Fallback bukan pengganti permanen, tapi bridge sementara.
- Semua fallback events harus di-reconcile ke Celestia saat recovery.

### Arsitektur Fallback

```
+---------------------------------------------+
|              DA Router                       |
+---------------------------------------------+
|  Primary: Celestia                           |
|  Secondary: Validator Quorum DA              |
|  Emergency: Self-hosted DA (Foundation)      |
+---------------------------------------------+
                    |
                    v
+---------------------------------------------+
|         Health Monitor                       |
|  - Celestia latency > 30s  -> WARNING        |
|  - Celestia down > 5min    -> FALLBACK       |
|  - Celestia down > 30min   -> EMERGENCY      |
+---------------------------------------------+
```

### Komponen Baru

#### 1. DA Health Monitor

```rust
struct DAHealthMonitor {
    celestia_latency_ms: AtomicU64,
    celestia_last_blob_height: AtomicU64,
    celestia_last_success: AtomicU64,
    fallback_active: AtomicBool,
    fallback_reason: RwLock<Option<String>>,
    current_status: RwLock<DAStatus>,
}

enum DAStatus {
    Healthy,      // Celestia normal
    Warning,      // Latency > 30s
    Degraded,     // Down > 5min, fallback active
    Emergency,    // Down > 30min, emergency DA active
    Recovering,   // Celestia back, reconciling
}
```

#### 2. Validator Quorum DA (Secondary)

```rust
trait QuorumDA: DALayer {
    fn quorum_threshold(&self) -> usize;  // e.g., 2/3 validators
    fn submit_with_signatures(&self, data: &[u8], sigs: Vec<Signature>) -> Result<BlobRef>;
    fn verify_quorum(&self, blob_ref: &BlobRef) -> Result<bool>;
}
```

#### 3. DA Router Implementation

```rust
impl DARouter {
    fn post_blob(&self, data: &[u8]) -> Result<BlobRef> {
        match self.health.status() {
            DAStatus::Healthy => self.celestia.post_blob(data),
            DAStatus::Warning => {
                // Post ke Celestia dengan extended timeout
                self.celestia.post_blob_with_timeout(data, extended_timeout)
            },
            DAStatus::Degraded => {
                // Post ke Validator Quorum DA
                // Tag dengan "pending_reconcile" flag
                self.validator_da.post_blob_tagged(data, PendingReconcile)
            },
            DAStatus::Emergency => {
                // Post ke Foundation emergency DA
                // Tag dengan "emergency_pending" flag
                self.emergency_da.post_blob_tagged(data, EmergencyPending)
            },
            DAStatus::Recovering => {
                // Post ke keduanya untuk consistency
                let celestia_ref = self.celestia.post_blob(data)?;
                self.reconcile_pending_blobs()?;
                Ok(celestia_ref)
            },
        }
    }

    fn get_blob(&self, blob_ref: &BlobRef) -> Result<Vec<u8>> {
        // Try Celestia first, fallback jika gagal
        match self.celestia.get_blob(blob_ref) {
            Ok(data) => Ok(data),
            Err(_) if self.health.is_fallback_active() => {
                self.validator_da.get_blob(blob_ref)
            },
            Err(e) => Err(e),
        }
    }
}
```

#### 4. Recovery dan Reconciliation

```rust
struct ReconciliationEngine {
    pending_blobs: Vec<PendingBlob>,
    reconciled_count: AtomicU64,
    last_reconcile: AtomicU64,
}

impl ReconciliationEngine {
    /// Saat Celestia recovery, semua pending blobs harus di-post ulang
    async fn reconcile(&self, celestia: &CelestiaDA) -> Result<ReconcileReport> {
        for pending in &self.pending_blobs {
            // Re-post ke Celestia dengan original sequence
            let ref_ = celestia.post_blob_with_sequence(
                &pending.data,
                pending.original_sequence
            ).await?;

            // Verify consistency
            self.verify_blob_consistency(&pending, &ref_)?;
        }
        Ok(report)
    }

    /// Verify state consistency antara fallback dan Celestia
    fn verify_state_consistency(&self) -> Result<ConsistencyReport>;
}
```

#### 5. Fallback Event Schema

```rust
enum FallbackEvent {
    FallbackActivated {
        reason: String,
        celestia_last_height: u64,
        activated_at: u64,
    },
    FallbackDeactivated {
        celestia_recovery_height: u64,
        blobs_reconciled: u64,
        deactivated_at: u64,
    },
    ReconciliationStarted {
        pending_count: u64,
        started_at: u64,
    },
    ReconciliationCompleted {
        reconciled_count: u64,
        failed_count: u64,
        completed_at: u64,
    },
}
```

#### 6. Health Check Thresholds (Configurable)

```rust
struct DAHealthConfig {
    warning_latency_ms: u64,        // default: 30_000 (30s)
    fallback_trigger_secs: u64,     // default: 300 (5min)
    emergency_trigger_secs: u64,    // default: 1800 (30min)
    health_check_interval_ms: u64,  // default: 5_000 (5s)
    max_reconcile_batch: usize,     // default: 100
}
```

### Validasi Wajib

- Celestia down --- fallback aktif dalam < 5 menit.
- Fallback blobs dapat dibaca oleh semua node.
- Celestia recovery --- reconciliation otomatis.
- State identical setelah reconciliation.
- Tidak ada blob loss selama fallback period.
- Sequence ordering tetap konsisten.
- Node dapat rebuild state dari fallback DA.
- Coordinator dapat rebuild state dari fallback DA.

### Kriteria Selesai

- Health monitor mendeteksi Celestia degradation dengan benar.
- Fallback activation otomatis berjalan sesuai threshold.
- Validator Quorum DA dapat menerima dan serve blobs.
- Emergency DA dapat menerima dan serve blobs.
- Reconciliation engine dapat sync semua pending blobs ke Celestia.
- State consistency verified setelah recovery.
- Semua tests passing untuk setiap failure scenario.

**Crates yang harus diubah / dilibatkan:** `common`, `coordinator`, `node`, `validator`, `proto`, `storage`, `ingress`, `agent`, `chain`.

**Catatan Penting:**

- Fallback DA tidak menggantikan Celestia secara permanen.
- Validator Quorum DA membutuhkan 2/3 validator signatures untuk validity.
- Emergency DA hanya digunakan jika Validator Quorum juga tidak tersedia.
- Semua fallback events wajib di-reconcile ke Celestia saat recovery.
- Tahap ini tidak mengubah trust model --- Celestia tetap source of truth.
- Fallback hanya menjamin liveness, bukan menggantikan data availability guarantee.

---

## Tahap 14A.2B.1 --- TSS Foundation dan Committee Structure

**Tujuan:** Membangun fondasi Threshold Signature Scheme (TSS) dan struktur data `CoordinatorCommittee` sebagai basis multi-coordinator system.

**Prinsip:**

- TSS implementation menggunakan FROST (Flexible Round-Optimized Schnorr Threshold).
- Semua types dan traits didefinisikan dengan jelas sebelum integrasi.
- Proto definitions lengkap untuk komunikasi antar coordinator.
- Tidak ada logic bisnis coordinator --- hanya foundation.

**Crates terlibat:** `crates/tss/` (baru), `crates/common/`, `crates/proto/`.

### Komponen

#### 1. Crate TSS (Baru)

File: `crates/tss/src/lib.rs`

**a) Key Generation (DKG --- Distributed Key Generation)**

```rust
struct DKGSession {
    session_id: SessionId,
    participants: Vec<ParticipantId>,
    threshold: u8,
    total: u8,
    state: DKGState,
}

enum DKGState {
    Round1Commitment,
    Round2Share,
    Completed(GroupPublicKey),
    Failed(DKGError),
}

trait DKGParticipant {
    fn generate_round1(&mut self) -> Round1Package;
    fn process_round1(&mut self, packages: Vec<Round1Package>) -> Result<Round2Package>;
    fn process_round2(&mut self, packages: Vec<Round2Package>) -> Result<KeyShare>;
}
```

**b) Threshold Signing**

```rust
struct SigningSession {
    session_id: SessionId,
    message: Vec<u8>,
    signers: Vec<SignerId>,
    threshold: u8,
    state: SigningState,
}

struct PartialSignature {
    signer_id: SignerId,
    signature: FrostSignatureShare,
    commitment: SigningCommitment,
}

struct AggregateSignature {
    signature: FrostSignature,
    signers: Vec<SignerId>,
    message_hash: Hash,
}

trait ThresholdSigner {
    fn create_commitment(&self) -> SigningCommitment;
    fn sign(&self, message: &[u8], commitments: &[SigningCommitment]) -> PartialSignature;
}

fn aggregate_signatures(
    partials: &[PartialSignature],
    group_pubkey: &GroupPublicKey,
) -> Result<AggregateSignature>;
```

**c) Verification**

```rust
fn verify_aggregate(
    signature: &AggregateSignature,
    message: &[u8],
    group_pubkey: &GroupPublicKey,
) -> bool;

fn verify_partial(
    partial: &PartialSignature,
    message: &[u8],
    participant_pubkey: &ParticipantPublicKey,
) -> bool;
```

**d) Key Share Management**

```rust
struct KeyShare {
    participant_id: ParticipantId,
    share: SecretShare,
    group_pubkey: GroupPublicKey,
    threshold: u8,
    total: u8,
}

impl KeyShare {
    fn public_share(&self) -> ParticipantPublicKey;
    fn serialize_encrypted(&self, key: &EncryptionKey) -> Vec<u8>;
    fn deserialize_encrypted(data: &[u8], key: &EncryptionKey) -> Result<Self>;
}
```

#### 2. Crate Common --- Committee Types

File: `crates/common/src/coordinator/mod.rs`

**a) CoordinatorCommittee Structure**

```rust
struct CoordinatorCommittee {
    members: Vec<CoordinatorMember>,
    threshold: u8,
    epoch: u64,
    epoch_start: Timestamp,
    epoch_duration_secs: u64,
    group_pubkey: GroupPublicKey,
}

struct CoordinatorMember {
    id: CoordinatorId,
    validator_id: ValidatorId,
    pubkey: ParticipantPublicKey,
    stake: u64,
}

impl CoordinatorCommittee {
    fn is_member(&self, id: &CoordinatorId) -> bool;
    fn get_member(&self, id: &CoordinatorId) -> Option<&CoordinatorMember>;
    fn is_epoch_valid(&self, timestamp: Timestamp) -> bool;
    fn epoch_remaining_secs(&self, now: Timestamp) -> u64;
}
```

**b) ThresholdReceipt Structure**

```rust
struct ThresholdReceipt {
    receipt_data: ReceiptData,
    aggregate_signature: AggregateSignature,
    signers: Vec<CoordinatorId>,
    epoch: u64,
    committee_hash: Hash,
}

struct ReceiptData {
    workload_id: WorkloadId,
    blob_hash: Hash,
    placement: Vec<NodeId>,
    timestamp: Timestamp,
    sequence: u64,
}

impl ThresholdReceipt {
    fn verify(&self, committee: &CoordinatorCommittee) -> bool;
    fn receipt_hash(&self) -> Hash;
}
```

**c) Committee Transition Types**

```rust
struct CommitteeTransition {
    from_epoch: u64,
    to_epoch: u64,
    old_committee: CoordinatorCommittee,
    new_committee: CoordinatorCommittee,
    handoff_start: Timestamp,
    handoff_end: Timestamp,
}

enum CommitteeStatus {
    Active,
    InHandoff { new_committee: CoordinatorCommittee },
    Expired,
}
```

#### 3. Crate Proto --- TSS Messages

File: `crates/proto/src/tss.proto`

**a) DKG Messages**

```protobuf
message DKGRound1Package {
    bytes session_id = 1;
    bytes participant_id = 2;
    bytes commitment = 3;
    bytes proof = 4;
}

message DKGRound2Package {
    bytes session_id = 1;
    bytes from_participant = 2;
    bytes to_participant = 3;
    bytes encrypted_share = 4;
}

message DKGResult {
    bytes session_id = 1;
    bytes group_pubkey = 2;
    repeated bytes participant_pubkeys = 3;
    uint32 threshold = 4;
}
```

**b) Signing Messages**

```protobuf
message SigningRequest {
    bytes session_id = 1;
    bytes message = 2;
    repeated bytes required_signers = 3;
    uint64 epoch = 4;
}

message SigningCommitmentMsg {
    bytes session_id = 1;
    bytes signer_id = 2;
    bytes commitment = 3;
}

message PartialSignatureMsg {
    bytes session_id = 1;
    bytes signer_id = 2;
    bytes signature_share = 3;
}

message AggregateSignatureMsg {
    bytes signature = 1;
    repeated bytes signer_ids = 2;
    bytes message_hash = 3;
}
```

**c) Committee Messages**

```protobuf
message CoordinatorCommitteeProto {
    repeated CoordinatorMemberProto members = 1;
    uint32 threshold = 2;
    uint64 epoch = 3;
    uint64 epoch_start = 4;
    uint64 epoch_duration_secs = 5;
    bytes group_pubkey = 6;
}

message ThresholdReceiptProto {
    ReceiptDataProto receipt_data = 1;
    AggregateSignatureMsg signature = 2;
    repeated bytes signer_ids = 3;
    uint64 epoch = 4;
    bytes committee_hash = 5;
}
```

### Validasi

**Unit Tests Wajib:**

- DKG round 1 generate valid commitments.
- DKG round 2 share distribution correct.
- DKG completes with valid group key.
- Threshold signing produces valid partial signatures.
- Aggregate signature verification passes.
- t-of-n signing works (e.g., 3-of-4).
- Invalid partial signature rejected.
- `CoordinatorCommittee` membership queries correct.
- `ThresholdReceipt` verification logic correct.
- Proto serialization/deserialization roundtrip.

**Integration Tests:**

- Full DKG ceremony with 4 participants.
- Signing session with threshold signers.
- Committee epoch validation.

### Kriteria Selesai

- `crates/tss/` compiles dan semua tests pass.
- DKG functional untuk 3-of-4 dan 5-of-7.
- Threshold signing functional.
- Proto definitions lengkap.
- Common types terintegrasi dengan tss.

---

## Tahap 14A.2B.2 --- Multi-Coordinator Integration dan Consensus

**Tujuan:** Mengintegrasikan TSS ke coordinator system dengan epoch rotation, multi-coordinator consensus, dan dispute resolution.

**Prinsip:**

- Coordinator selection deterministic dari DA seed.
- Epoch rotation smooth tanpa service disruption.
- Dispute resolution on-chain dan verifiable.
- Single coordinator down tidak menghentikan sistem.

**Crates terlibat:** `crates/coordinator/`, `crates/validator/`, `crates/chain/`.

### Komponen

#### 1. Crate Validator --- Coordinator Selection

File: `crates/validator/src/coordinator_selection.rs`

**a) Selection Algorithm**

```rust
struct CoordinatorSelector {
    validators: Vec<Validator>,
    committee_size: u8,
    threshold: u8,
}

impl CoordinatorSelector {
    fn select_committee(
        &self,
        epoch: u64,
        seed: Hash,  // from DA blob at epoch start
    ) -> CoordinatorCommittee {
        // Stake-weighted random selection
        // Deterministic based on seed
    }

    fn compute_selection_weights(&self) -> Vec<(ValidatorId, u64)>;

    fn deterministic_shuffle(
        candidates: &[Validator],
        seed: Hash,
    ) -> Vec<Validator>;
}
```

**b) Epoch Seed Derivation**

```rust
fn derive_epoch_seed(
    epoch: u64,
    da_blob_hash: Hash,
    prev_committee_hash: Hash,
) -> Hash;

fn verify_epoch_seed(
    seed: Hash,
    epoch: u64,
    da_proof: &DAMerkleProof,
) -> bool;
```

**c) Committee Verification**

```rust
fn verify_committee_selection(
    committee: &CoordinatorCommittee,
    validators: &[Validator],
    seed: Hash,
) -> bool;
```

#### 2. Crate Coordinator --- Multi-Coordinator Consensus

File: `crates/coordinator/src/multi/mod.rs`

**a) Multi-Coordinator Node**

```rust
struct MultiCoordinator {
    id: CoordinatorId,
    key_share: KeyShare,
    committee: CoordinatorCommittee,
    peers: HashMap<CoordinatorId, PeerConnection>,
    pending_receipts: HashMap<WorkloadId, PendingReceipt>,
    tss_sessions: HashMap<SessionId, SigningSession>,
}

impl MultiCoordinator {
    async fn propose_receipt(&mut self, data: ReceiptData) -> Result<ThresholdReceipt>;
    async fn participate_signing(&mut self, request: SigningRequest) -> Result<()>;
    async fn handle_peer_message(&mut self, from: CoordinatorId, msg: CoordinatorMessage);
}
```

**b) Consensus Protocol**

```rust
struct ReceiptConsensus {
    workload_id: WorkloadId,
    proposed_data: ReceiptData,
    votes: HashMap<CoordinatorId, Vote>,
    state: ConsensusState,
}

enum ConsensusState {
    Proposed,
    Voting,
    Signing,
    Completed(ThresholdReceipt),
    Failed(ConsensusError),
}

enum Vote {
    Approve,
    Reject(String),
}

impl ReceiptConsensus {
    fn add_vote(&mut self, from: CoordinatorId, vote: Vote) -> ConsensusState;
    fn should_proceed_to_signing(&self, threshold: u8) -> bool;
}
```

**c) Coordinator Communication**

```rust
enum CoordinatorMessage {
    ProposeReceipt(ReceiptData),
    VoteReceipt { workload_id: WorkloadId, vote: Vote },
    SigningCommitment(SigningCommitmentMsg),
    PartialSignature(PartialSignatureMsg),
    EpochHandoff(CommitteeTransition),
}

trait CoordinatorNetwork {
    async fn broadcast(&self, msg: CoordinatorMessage);
    async fn send_to(&self, target: CoordinatorId, msg: CoordinatorMessage);
    async fn receive(&mut self) -> (CoordinatorId, CoordinatorMessage);
}
```

**d) Optimistic Receipts (Low Latency Option)**

```rust
struct OptimisticReceipt {
    receipt_data: ReceiptData,
    single_signature: Signature,
    coordinator_id: CoordinatorId,
    challenge_window: Duration,
}

impl OptimisticReceipt {
    fn is_challengeable(&self, now: Timestamp) -> bool;
    fn upgrade_to_threshold(&self, threshold_receipt: ThresholdReceipt) -> ThresholdReceipt;
}
```

#### 3. Crate Chain --- Epoch Rotation dan Disputes

File: `crates/chain/src/coordinator/epoch.rs`

**a) Epoch Management**

```rust
struct EpochManager {
    current_epoch: u64,
    current_committee: CoordinatorCommittee,
    next_committee: Option<CoordinatorCommittee>,
    epoch_duration: Duration,
    handoff_duration: Duration,
    selector: CoordinatorSelector,
}

impl EpochManager {
    fn current_status(&self, now: Timestamp) -> CommitteeStatus;
    async fn trigger_rotation(&mut self, da_seed: Hash) -> Result<CommitteeTransition>;
    fn is_in_handoff(&self, now: Timestamp) -> bool;
    fn valid_committee_for_timestamp(&self, ts: Timestamp) -> &CoordinatorCommittee;
}
```

**b) DKG Coordination for New Epoch**

```rust
struct EpochDKG {
    target_epoch: u64,
    new_members: Vec<CoordinatorMember>,
    dkg_session: DKGSession,
    state: EpochDKGState,
}

enum EpochDKGState {
    Pending,
    Round1InProgress,
    Round2InProgress,
    Completed(GroupPublicKey),
    Failed(DKGError),
}

impl EpochDKG {
    async fn run_dkg(&mut self) -> Result<GroupPublicKey>;
}
```

**c) Dispute Resolution**

File: `crates/chain/src/coordinator/disputes.rs`

```rust
enum CoordinatorDispute {
    InconsistentScheduling {
        receipt_a: ThresholdReceipt,
        receipt_b: ThresholdReceipt,
        da_proof: DAMerkleProof,
    },
    InvalidSignature {
        receipt: ThresholdReceipt,
        expected_committee: CoordinatorCommittee,
    },
    MissingReceipt {
        expected_workload_id: WorkloadId,
        da_proof: DAMerkleProof,
        timeout_proof: TimeoutProof,
    },
    UnauthorizedSigner {
        receipt: ThresholdReceipt,
        invalid_signer: CoordinatorId,
    },
}

struct DisputeResolution {
    dispute: CoordinatorDispute,
    evidence: DisputeEvidence,
    result: Option<DisputeResult>,
}

enum DisputeResult {
    Valid { slash_targets: Vec<CoordinatorId>, slash_amount: u64 },
    Invalid { reason: String },
    Inconclusive { requires_governance: bool },
}

trait DisputeResolver {
    fn validate_dispute(&self, dispute: &CoordinatorDispute) -> bool;
    fn resolve(&self, dispute: &CoordinatorDispute) -> DisputeResult;
    fn apply_slashing(&mut self, result: &DisputeResult) -> Result<()>;
}
```

**d) Accountability Logging**

```rust
struct CoordinatorAccountability {
    coordinator_id: CoordinatorId,
    epoch: u64,
    decisions: Vec<AccountableDecision>,
}

struct AccountableDecision {
    workload_id: WorkloadId,
    decision: ReceiptData,
    merkle_proof: DAMerkleProof,
    timestamp: Timestamp,
}

impl CoordinatorAccountability {
    fn log_decision(&mut self, decision: AccountableDecision);
    fn verify_decision(&self, decision: &AccountableDecision) -> bool;
    fn generate_proof(&self, workload_id: WorkloadId) -> Option<AccountabilityProof>;
}
```

### Validasi

**Unit Tests Wajib:**

- Coordinator selection deterministic for same seed.
- Stake-weighted selection proportional.
- Committee verification correct.
- Receipt consensus reaches agreement.
- Threshold signing in consensus flow.
- Epoch rotation triggers at correct time.
- Handoff period allows both committees.
- DKG runs successfully for new epoch.
- Dispute detection for inconsistent scheduling.
- Dispute resolution slashes correct coordinators.
- Optimistic receipt upgrade works.

**Integration Tests:**

- Full epoch rotation cycle.
- Multi-coordinator receipt generation.
- Coordinator failure tolerance (1 of 4 down).
- Dispute submission and resolution.
- Handoff with active receipt processing.

**Fault Tolerance Tests:**

- Single coordinator down --- sistem tetap berjalan.
- Majority coordinator down --- sistem degraded tapi tidak mati.
- Coordinator collusion (< threshold) --- tidak bisa forge receipt.
- Network partition recovery.

### Kriteria Selesai

- Coordinator selection functional dan verifiable.
- Multi-coordinator consensus untuk receipt.
- Epoch rotation automated setiap 6 jam.
- Handoff period (15 menit) smooth.
- Dispute resolution mechanism active.
- Slashing hooks terintegrasi.
- Latency overhead < 200ms per receipt.

### Ringkasan Pembagian

**Tahap 14A.2B.1 (Foundation):**

- Crates: `tss` (baru), `common`, `proto`.
- Fokus: TSS implementation, types, proto definitions.
- Output: Library siap pakai untuk threshold signing.
- Estimasi: 40--50% total effort.

**Tahap 14A.2B.2 (Integration):**

- Crates: `coordinator`, `validator`, `chain`.
- Fokus: Selection, consensus, rotation, disputes.
- Output: Fully functional multi-coordinator system.
- Estimasi: 50--60% total effort.

**Dependency:** 14A.2B.1 harus selesai sebelum 14A.2B.2 dimulai. 14A.2B.2 depends on types dan TSS dari 14A.2B.1.

---

## Tahap 14B --- Stake dan Identity Gating (Security-First, No Economy)

**Tujuan:** Mengunci siapa yang boleh menjadi node sebelum sistem ekonomi hidup. Tahap ini memisahkan security bugs dari economic bugs.

**Prinsip Penting:**

- Node tidak boleh aktif tanpa verifikasi stake dan identitas.
- Reward belum ada.
- Receipt belum ada.

### Mekanisme Baru

#### 1. Node Identity

Setiap node wajib memiliki: TLS certificate valid, Ed25519 `node_id`, `operator_address` (wallet).

#### 2. Chain API Wajib

Expose di Chain Nusantara: `get_stake(address)`, `get_node_class(address)`, `get_slashing_status(address)`.

#### 3. Coordinator Gatekeeping

Coordinator reject node jika: stake < 500 / 5000, slashing cooldown aktif, TLS invalid, `node_id` tidak sesuai operator.

#### 4. Node Lifecycle

Status node: `Pending`, `Active`, `Quarantined`, `Banned`. Node tidak akan di-schedule kecuali status = `Active`.

### Validasi Wajib

- Node tanpa stake --- ditolak.
- Node stake kurang --- quarantined.
- Node pernah slashing --- cooldown enforced.
- Identity spoofing --- gagal join.

### Kriteria Selesai

- Hanya node valid yang aktif.
- Scheduler tidak bisa memilih node ilegal.
- Sistem aman tanpa reward aktif.

**Crates terlibat:** `coordinator`, `node`, `validator`, `chain`, `agent`, `common`.

> Mekanisme stake pada tahap ini hanya berfungsi sebagai security gate, dan bukan sinyal ekonomi, ROI, atau insentif partisipasi publik. Keberhasilan tahap ini tidak boleh ditafsirkan sebagai aktivasi ekonomi jaringan atau indikator kelayakan ROI bagi operator.

---

## Tahap 14C.A — Receipt Foundation & Chain Validation

**Tujuan:** Mendefinisikan struktur data ekonomi (ExecutionCommitment, ReceiptV1),
mengimplementasikan validasi chain-side, dan menyiapkan coordinator untuk threshold-sign receipt.

**Crates terlibat:** `proto`, `common`, `chain`, `coordinator`

### Scope

1. **`proto`** — Definisi protobuf/message types:
   - Tambah message `ExecutionCommitment` (workload_id, input_hash, output_hash,
     state_root_before, state_root_after, execution_trace_merkle_root).
   - Tambah message `ReceiptV1` (workload_id, node_id, usage_proof_hash,
     execution_commitment, coordinator_threshold_signature, node_signature,
     submitter_address).
   - Tambah message `ClaimReward` request/response.
   - Tambah message `FraudProofChallenge` (placeholder, belum ada logic).

2. **`common`** — Shared types dan utility:
   - Type alias dan helper untuk `WorkloadId`, `UsageProofHash`, `ExecutionCommitment`.
   - Fungsi hashing deterministic untuk execution commitment fields.
   - Konstanta ekonomi: rasio distribusi (70/20/10), challenge period duration (1 hour).
   - Anti-self-dealing helper: fungsi `is_self_dealing(node_owner, submitter)`.

3. **`chain`** — On-chain validation dan reward logic:
   - Implementasi `ClaimReward` transaction handler.
   - Validasi receipt: threshold signature valid, stake sufficient,
     no duplicate receipt, anti-self-dealing check.
   - Validasi execution commitment: hash consistency, fields non-empty.
   - Reward distribution logic: 70% node, 20% validator, 10% treasury (fixed, no burn).
   - Challenge period state: compute receipts masuk pending state selama 1 jam,
     storage receipts langsung distribute.
   - Reject logic: duplicate receipt, self-dealing, invalid signature, invalid commitment.

4. **`coordinator`** — Threshold signing receipt:
   - Coordinator menerima usage proof + execution commitment dari node.
   - Verifikasi dasar: workload terdaftar, node eligible, proof format valid.
   - Threshold-sign receipt menggunakan FROST (memanggil TSS, tapi TSS integration
     dilakukan di 14C.C — di sini cukup define interface/trait).
   - Return signed `ReceiptV1` ke node untuk di-submit ke chain.

### Kriteria Selesai 14C.A

- Semua proto message terdefinisi dan bisa di-serialize/deserialize.
- `chain` bisa menerima `ClaimReward`, validasi lengkap, dan distribute reward
  (dengan mock signature untuk testing).
- `coordinator` punya flow: terima proof → validasi → sign receipt (mock TSS).
- Anti-self-dealing test pass.
- Duplicate receipt rejection test pass.
- Challenge period state untuk compute receipt tercatat di chain.

---

## Tahap 14C.B — Node Execution & Runtime Integration

**Tujuan:** Node menghasilkan execution commitment yang valid dari actual workload execution,
dan runtime (WASM + VM) memproduksi output yang bisa di-commit.

**Crates terlibat:** `node`, `runtime_wasm`, `runtime_vm`

### Scope

1. **`runtime_wasm`** — WASM runtime menghasilkan verifiable output:
   - Setelah eksekusi workload, capture: input_hash, output_hash,
     state_root_before, state_root_after.
   - Generate execution_trace_merkle_root dari execution steps
     (sederhana, bukan full fraud proof — preparation saja).
   - Return `ExecutionCommitment` struct ke caller (node).
   - Eksekusi harus deterministic: input yang sama → commitment yang sama.

2. **`runtime_vm`** — VM runtime (non-WASM) menghasilkan verifiable output:
   - Sama seperti `runtime_wasm`: capture state transitions dan produce commitment.
   - Pastikan output format `ExecutionCommitment` identik dengan WASM path.
   - Deterministic execution guarantee untuk VM-based workloads.

3. **`node`** — Orchestrasi execution → commitment → receipt submission:
   - Node menerima workload assignment.
   - Dispatch ke `runtime_wasm` atau `runtime_vm` sesuai workload type.
   - Terima `ExecutionCommitment` dari runtime.
   - Buat `UsageProof` (resource usage selama execution).
   - Kirim (usage_proof + execution_commitment) ke coordinator untuk di-sign.
   - Terima signed `ReceiptV1` dari coordinator.
   - Submit `ClaimReward` transaction ke chain.
   - Handle response: reward success, rejection reason, atau challenge period status.

### Kriteria Selesai 14C.B

- WASM workload menghasilkan `ExecutionCommitment` yang deterministic
  (run 2x dengan input sama → commitment identik).
- VM workload menghasilkan `ExecutionCommitment` dengan format identik.
- Node bisa execute workload → produce commitment → kirim ke coordinator
  → terima signed receipt → submit ke chain → terima reward.
- End-to-end flow test: node execute → chain distribute reward (dengan mock coordinator).
- Storage workload vs compute workload dibedakan
  (storage = immediate, compute = challenge period).

---

## Tahap 14C.C — TSS Integration, Validator Reward & System Wiring

**Tujuan:** Menyambungkan semua komponen: TSS real signing, validator menerima bagian reward,
agent/ingress routing, dan DA log sinkronisasi.

**Crates terlibat:** `tss`, `validator`, `agent`, `ingress`

### Scope

1. **`tss`** — Real threshold signing untuk receipt:
   - Ganti mock TSS di coordinator dengan real FROST threshold signature.
   - Coordinator collect partial signatures dari TSS participants.
   - Threshold tercapai → produce valid `FrostSignature` untuk receipt.
   - Chain-side verification menggunakan aggregated public key.
   - Error handling: threshold tidak tercapai, participant timeout, invalid partial sig.

2. **`validator`** — Validator menerima reward share:
   - Validator yang aktif di epoch berhak atas 20% reward dari setiap receipt.
   - Distribusi ke validator set proporsional (atau equal split — tentukan di sini).
   - Validator bisa query pending rewards dan claimed rewards.
   - Pastikan validator reward hanya dari receipt yang sudah finalized
     (compute: setelah challenge period lewat tanpa fraud proof).

3. **`agent`** — Orchestrasi flow ekonomi end-to-end:
   - Agent mengelola lifecycle: workload dispatch → execution → receipt → claim.
   - Monitoring: track receipt status (pending, challenged, finalized, rejected).
   - Retry logic: jika submission gagal, retry dengan backoff.
   - Metrics/logging: catat semua economic events untuk observability.

4. **`ingress`** — Routing dan endpoint untuk economic transactions:
   - Expose RPC/API endpoint untuk `ClaimReward` submission.
   - Expose endpoint untuk query receipt status dan reward balance.
   - Expose endpoint untuk fraud proof submission (placeholder — accept tapi belum process).
   - Rate limiting dan basic validation sebelum forward ke chain.

### Kriteria Selesai 14C.C

- Receipt di-sign dengan real FROST threshold signature (bukan mock).
- Chain verify real threshold signature dan distribute reward.
- Validator menerima 20% share dari finalized receipt.
- Agent bisa orchestrate full flow tanpa manual intervention.
- Ingress endpoints bisa menerima ClaimReward dan return status.
- Full integration test: node execute → commitment → coordinator TSS sign
  → submit via ingress → chain validate → reward distribute
  (70% node, 20% validator, 10% treasury).
- DA log mencatat semua receipt events.
- Anti-self-dealing, duplicate rejection, dan challenge period
  berfungsi di full integrated flow.

---

## Ringkasan Dependency
```
14C.A (proto, common, chain, coordinator)
  ↓
14C.B (node, runtime_wasm, runtime_vm)
  ↓
14C.C (tss, validator, agent, ingress)
```

- **14C.A** harus selesai duluan: tanpa proto types dan chain validation,
  node dan runtime tidak tahu format apa yang harus diproduksi.
- **14C.B** bergantung pada 14C.A: node perlu tahu format receipt
  dan coordinator interface untuk submit.
- **14C.C** bergantung pada 14C.A + 14C.B: TSS mengganti mock,
  validator reward butuh chain logic yang sudah jalan,
  agent/ingress butuh semua komponen ready.

---

## Tahap 15 --- Logging, Audit, Metrics (WORM + DA Mirror)

**Perubahan dari blueprint:** Audit log penting harus disimpan lokal sebagai WORM dan dipost ke Celestia DA untuk immutability.

**Tambahan log wajib:**

- Slashing events.
- Stake updates.
- Anti-self-dealing violation logs.
- User-controlled delete.
- DA-sync sequence number.
- Governance proposal + delay window.
- Coordinator committee rotation events (baru).
- DA fallback activation/deactivation events (baru).
- Compute challenge events.

**Selesai jika:** Log--DA sync mirror 100% match.

**Crates yang harus diubah / dilibatkan:** `coordinator`, `storage`, `proto`, `chain`, `node`, `validator`, `agent`, `ingress`, `common`.

> Audit log pada fase ini belum bersifat compliance-grade untuk publik, dan hanya digunakan untuk internal verification dan forensik.

---

## Tahap 16 --- TLS + Node ID + Stake Verification

**Yang baru:**

Coordinator harus menolak node yang: TLS sertifikat invalid, stake kurang (500 / 5000), identitas operator tidak cocok, pernah kena slashing cooldown.

Chain Nusantara harus expose API:

```
get_stake(address)
get_node_class(address)
check_slashing_status(address)
```

Coordinator baru boleh menerima node setelah semua cek lulus.

**Crates yang harus diubah / dilibatkan:** `coordinator`, `node`, `validator`, `chain`, `agent`, `common`.

> Verifikasi identitas dan stake tidak memberikan kepercayaan operasional terhadap node, melainkan hanya menetapkan kelayakan minimum untuk berpartisipasi. Node tetap diperlakukan sebagai untrusted dalam semua aspek eksekusi dan penyimpanan.

---

## Tahap 17 --- Penjadwalan (Anti-Self-Dealing + Stake Weight)

**Formula baru:**

```
S = w1*CPU + w2*RAM + w3*GPU + w4*(1/latency)
  - w5*IO_pressure + w6*class_weight + w7*stake_weight
```

**Stake Weight:**

- Node reguler: `log2(stake / 500)`
- Node DC: `log2(stake / 5000)`

**Bootstrap system di masa mendatang**
- Node identity (`node_id`, Ed25519 public key) yang sudah diimplementasi di tahap ini juga digunakan sebagai peer ID dalam bootstrap system (28.1). Pastikan `node_id` format compatible dengan peer identification di bootstrap handshake.
- Tidak ada perubahan implementasi, hanya catatan forward-compatibility.

**Anti-Self-Dealing:** Scheduler harus skip node jika `owner(node) == submitter(tx)` atau ada hubungan wallet-affinity on-chain.

**Crates yang harus diubah / dilibatkan:** `coordinator`, `node`, `storage`, `chain`, `validator`, `ingress`.

> Stake weight tidak boleh dipresentasikan sebagai power metric ke publik pada fase ini. Stake weight digunakan semata-mata sebagai sinyal keamanan dan komitmen jangka panjang, bukan sebagai representasi kekuasaan, reputasi, atau hak istimewa node. Scheduler tetap memprioritaskan performa teknis dan anti-self-dealing.

---

## Tahap 18 --- Runtime WASM dan MicroVM (With Gas Meter v2)

**Resource meter harus output:** `compute_cycles`, `mem_usage`, `fs_ops`, `network_out`, `gpu_cycles`, `execution_trace` (untuk fraud proof).

### Execution Trace

```rust
struct ExecutionTrace {
    checkpoints: Vec<StateCheckpoint>,
    instruction_count: u64,
    memory_accesses: Vec<MemoryAccess>,
    io_operations: Vec<IOOperation>,
}

struct StateCheckpoint {
    instruction_index: u64,
    state_root: Hash,
    memory_root: Hash,
}
```

**Crates yang harus diubah / dilibatkan:** `runtime_wasm`, `runtime_vm`, `coordinator`, `node`, `chain`, `common`.

> Resource metering dan `runtime_usage_proof` pada tahap ini dirancang agar dapat diverifikasi ulang oleh pihak ketiga, sehingga tidak ada keharusan mempercayai node maupun coordinator.

---

## Tahap 18.1 --- User Intent Model (Intent > Config)

**Tujuan:** Mengganti config eksplisit dengan intent deklaratif.

User tidak: memilih node, memilih RF, memilih zona, memilih class.

User hanya menyatakan:

```yaml
intent:
  type: web_app | batch | static | ai
  priority: low | normal | high
  visibility: private | public
```

### Implementasi Teknis

Crate baru: `crates/ux_intent/`

Struktur: `IntentSpec`, `IntentValidator`, `IntentCompiler`.

**Flow:**

```
IntentSpec -> validate() -> compile() -> InternalWorkloadSpec
```

`InternalWorkloadSpec` berisi: class preference, SLA tier, replication hint, cost ceiling (soft).

User tidak bisa override hasil compile, kecuali advanced mode (belum aktif).

**Crates terlibat:** `agent`, `ingress`, `coordinator`, `common`, `ux_intent` (baru).

**Selesai jika:** User hanya mengisi intent, sistem menghasilkan workload spec lengkap, tidak ada config teknis di UX.

---

## Tahap 18.2 --- Smart Default Engine (Auto Decision Core)

**Tujuan:** Menghilangkan decision fatigue user.

**Prinsip:** Kalau user tidak bilang apa-apa --- sistem memilih aman + murah + stabil.

Komponen baru: `crates/ux_defaults/`

**Default Rules (contoh):**

- `visibility = private` --- encrypted + no ingress.
- `ai workload` --- prefer node DC.
- `priority = low` --- allow latency tradeoff.
- `batch job` --- spot-style scheduling.

**Integrasi:** Dipanggil oleh `IntentCompiler`. Output --- `ResolvedWorkloadSpec`.

**Crates terlibat:** `coordinator`, `node`, `runtime_wasm`, `runtime_vm`, `ux_defaults`.

**Selesai jika:** Semua intent valid tanpa config tambahan, tidak ada mandatory flag selain intent.

---

## Tahap 18.3 --- Auto Resource Classification

**Tujuan:** User tidak memilih CPU/RAM/GPU.

**Mekanisme:**

1. Dry-run execution (sandboxed).
2. Estimate: CPU cycles, memory peak, IO pressure.
3. Tentukan: node class, runtime, billing tier (internal).

**Tambahan struct:**

```rust
ResourceEstimate {
    cpu,
    mem,
    io,
    gpu_optional,
}
```

**Crates yang dilibatkan:** `runtime_wasm`, `runtime_vm`, `coordinator`, `node`.

**Selesai jika:** User tidak pernah set resource manual, scheduler dapat input akurat.

---

## Tahap 18.4 --- One-Command Deploy Pipeline (Agent Side)

**Tujuan:** User deploy cukup:

```bash
dsdn deploy .
```

**Flow:**

Agent melakukan: detect project type, build artifact (WASM / VM), generate `IntentSpec`, upload, run, return endpoint / `job_id`.

**Implementasi:** Tambahan di agent: `deploy.rs`, `detect.rs`, `packager.rs`.

**Crates terlibat:** `agent`, `ux_intent`, `ux_defaults`, `ingress`, `coordinator`.

**Selesai jika:** Satu command = deploy, tidak ada file config wajib.

---

## Tahap 18.5 --- Human Error Translation Layer

**Tujuan:** Error tidak bocorkan arsitektur internal.

**Contoh:**

- Sebelum: `replica quorum not met`
- Sesudah: `Sistem sedang memindahkan workload. Estimasi 30-60 detik.`

**Implementasi:** Crate baru: `crates/ux_errors/`. Mapping: `InternalError -> UserFacingError`.

**Crates terlibat:** `coordinator`, `node`, `ingress`, `agent`, `ux_errors`.

**Selesai jika:** Tidak ada error teknis mentah ke user, semua error punya message manusiawi.

---

## Tahap 18.6 --- Progressive Disclosure UI Contract

**Tujuan:** Transparan tanpa menakut-nakuti.

**Level Output:**

- Level 0: "Running"
- Level 1: latency, status
- Level 2: receipt hash, DA ref
- Level 3: full audit trace

**Implementasi:** Semua API response punya:

```json
{
  "summary": {},
  "details": {},
  "audit": {}
}
```

UI memilih level.

**Crates terlibat:** `ingress`, `agent`, `proto`, `common`.

**Selesai jika:** UX simpel default, auditor tetap dapat semua data.

---

## Tahap 18.7 --- Zero-Knowledge UX Contract (No Trust Leak)

**Tujuan:** UX tidak menjadi trust surface baru.

**Aturan Wajib:**

- UX tidak simpan state.
- UX tidak tanda tangan receipt.
- UX hanya consumer DA-derived state.

**Validasi:**

- Kill UX layer --- sistem tetap hidup.
- Replay DA --- UX tampil identik.

**Crates terlibat:** `ingress`, `agent`, `coordinator`, `common`.

**Selesai jika:** UX sepenuhnya stateless, tidak ada authority baru.

---

## Tahap 18.8 --- Compute Fraud Proof System [Critical]

**Tujuan:** Mengimplementasikan sistem fraud proof untuk verifikasi compute, menghilangkan blind spot terbesar dalam arsitektur DSDN.

**Prinsip Penting:**

- Default: Optimistic execution (hasil diterima setelah challenge period).
- Siapapun bisa challenge dengan fraud proof.
- Fraud proof harus murah untuk verify, mahal untuk fake.
- Node yang terbukti curang di-slash.

### Arsitektur Fraud Proof

```
+---------------------------------------------+
|              Compute Execution               |
|                                              |
|  Node executes workload                      |
|  -> Generates ExecutionCommitment            |
|  -> Generates ExecutionTrace (merkleized)    |
|  -> Submits to Coordinator Committee         |
+---------------------------------------------+
                    |
                    v
+---------------------------------------------+
|       Challenge Period (1-4 hours)           |
|                                              |
|  Receipt visible on DA                       |
|  Anyone can download and verify              |
|  If invalid -> submit FraudProof             |
+---------------------------------------------+
                    |
          +---------+---------+
          |                   |
          v                   v
+-----------------+  +-----------------+
|  No Challenge   |  |  Challenge      |
|  -> Reward paid |  |  -> Arbitration |
+-----------------+  +-----------------+
```

### Komponen Baru

#### 1. Execution Trace Merkleization

```rust
struct MerkleizedTrace {
    root: Hash,
    depth: u32,
    checkpoints: Vec<StateCheckpoint>,
}

impl MerkleizedTrace {
    fn get_checkpoint(&self, index: u64) -> (StateCheckpoint, MerkleProof);
    fn verify_transition(
        &self,
        from_index: u64,
        to_index: u64,
        proof: &MerkleProof,
    ) -> bool;
}
```

#### 2. Fraud Proof Structure

```rust
struct FraudProof {
    receipt: ThresholdReceipt,
    dispute_type: DisputeType,
    evidence: FraudEvidence,
    challenger: Address,
    bond: Amount,  // challenger harus stake
}

enum DisputeType {
    InvalidOutput {
        claimed_output: Hash,
        correct_output: Hash,
        proof: ReExecutionProof,
    },
    InvalidStateTransition {
        checkpoint_before: StateCheckpoint,
        checkpoint_after: StateCheckpoint,
        transition_proof: MerkleProof,
    },
    FakeExecution {
        // Node claim execute tapi tidak benar-benar run
        challenge_input: Vec<u8>,
        expected_checkpoint: StateCheckpoint,
    },
}
```

#### 3. Interactive Verification Game (untuk dispute besar)

```rust
// Bisection protocol untuk find exact point of disagreement
struct VerificationGame {
    receipt: ThresholdReceipt,
    challenger: Address,
    defender: Address,  // node
    current_range: (u64, u64),
    challenger_claim: StateCheckpoint,
    defender_claim: StateCheckpoint,
    rounds: Vec<BisectionRound>,
    deadline: Timestamp,
}

impl VerificationGame {
    fn bisect(&mut self, side: GameSide, claim: StateCheckpoint);
    fn resolve(&self) -> GameResult;
}
```

#### 4. Challenge Window Configuration

```rust
struct ChallengeConfig {
    // Window duration based on workload size
    base_window: Duration,           // 1 hour
    per_mb_addition: Duration,       // +10 min per MB output
    max_window: Duration,            // 4 hours

    // Bond requirements
    challenger_bond: Amount,         // 100 NUSA
    defender_bond: Amount,           // already staked as node

    // Slashing
    fraud_slash_percent: u8,                // 10%
    false_accusation_slash_percent: u8,     // 5% of challenger bond
}
```

#### 5. Fraud Proof Verification (On-chain)

```rust
fn verify_fraud_proof(proof: &FraudProof) -> FraudVerdict {
    match &proof.dispute_type {
        DisputeType::InvalidOutput { claimed, correct, proof } => {
            // Re-execute small segment to verify
            let verified_output = execute_segment(proof);
            if verified_output != claimed {
                FraudVerdict::FraudConfirmed
            } else {
                FraudVerdict::FalseAccusation
            }
        },
        DisputeType::InvalidStateTransition { before, after, proof } => {
            // Verify merkle proof and state transition
            if !verify_transition(before, after, proof) {
                FraudVerdict::FraudConfirmed
            } else {
                FraudVerdict::FalseAccusation
            }
        },
        DisputeType::FakeExecution { input, expected } => {
            // Execute challenge input, compare checkpoint
            let actual = execute_and_checkpoint(input);
            if actual != expected {
                FraudVerdict::FraudConfirmed
            } else {
                FraudVerdict::FalseAccusation
            }
        },
    }
}
```

#### 6. Redundant Execution Mode

```rust
struct RedundantExecutionConfig {
    enabled: bool,
    replica_count: u8,       // 2 or 3
    consensus: ConsensusMode, // Majority or Unanimous
    cost_multiplier: f64,    // 2.0x or 3.0x
}
```

Untuk workload critical, user bisa request redundant execution:

1. Node receives workload.
2. Node executes dengan trace generation.
3. Node generates `ExecutionCommitment`.
4. Node submits to Coordinator Committee.
5. Committee threshold-signs receipt.
6. Receipt posted to DA.
7. Challenge period starts (1--4 hours).
8. If challenged: Challenger submits FraudProof + bond. If simple dispute --- immediate verification. If complex dispute --- interactive game. Loser gets slashed.
9. If not challenged: Reward distributed to node.

### Validasi Wajib

- Fraud proof dapat detect fake execution.
- Fraud proof dapat detect wrong output.
- Interactive game converges to single instruction.
- Slashing works correctly.
- Challenge bond prevents spam.

### Kriteria Selesai

- `ExecutionTrace` generation functional.
- Merkleized trace verifiable.
- FraudProof submission and verification.
- Interactive game implementation.
- Slashing integration.
- Redundant execution mode (optional).

**Crates terlibat:** `runtime_wasm`, `runtime_vm`, `chain`, `coordinator`, `node`, `validator`, `proto`, `common`.

**Crate baru:** `crates/fraud_proof/` --- Fraud proof logic and verification.

**Catatan Penting:**

- Fraud proof menambah kompleksitas dan latency.
- Trade-off: security vs performance.
- Untuk workload non-critical, challenge period bisa dikurangi.
- TEE-based attestation (SGX/SEV) bisa bypass fraud proof jika tersedia.

---

## Tahap 18.9 --- SDK dan Developer Experience

**Tujuan:** Membangun SDK dan tooling yang membuat development di DSDN lebih mudah dari AWS/GCP, sebagai competitive moat.

**Prinsip Penting:**

- Developer experience adalah moat yang susah ditiru.
- Documentation dalam Bahasa Indonesia dan English.
- One-click deployment untuk common use cases.
- Error messages yang helpful.

### Komponen

#### 1. DSDN SDK (Multi-language)

```
crates/sdk_rust/     -- Native Rust SDK
sdks/sdk_python/     -- Python SDK
sdks/sdk_js/         -- JavaScript/TypeScript SDK
sdks/sdk_go/         -- Go SDK
```

#### 2. SDK Core Features

```rust
// Rust SDK example
use dsdn_sdk::prelude::*;

#[tokio::main]
async fn main() {
    let client = DSDN::connect("mainnet").await?;

    // Storage
    let cid = client.storage()
        .upload_file("./my_data.csv")
        .encrypted(true)
        .build()
        .await?;

    // Compute
    let result = client.compute()
        .deploy_wasm("./my_module.wasm")
        .intent(Intent::Batch { priority: Priority::Normal })
        .build()
        .await?;

    // Wait for result
    let output = result.wait_with_progress(|p| {
        println!("Progress: {}%", p.percent);
    }).await?;
}
```

#### 3. Project Templates

```bash
dsdn init --template web-app       # Static site + API
dsdn init --template ai-inference  # AI model serving
dsdn init --template data-pipeline # Batch processing
dsdn init --template storage-only  # Just storage
```

#### 4. Local Development Environment

```bash
dsdn dev start   # Start local DSDN network
dsdn dev deploy  # Deploy to local
dsdn dev logs    # Stream logs
dsdn dev shell   # Interactive shell
```

#### 5. Documentation Site

```
docs/
├── id/                 # Indonesian docs
│   ├── quickstart.md
│   ├── tutorials/
│   ├── api-reference/
│   └── troubleshooting/
├── en/                 # English docs
└── examples/           # Code examples
```

#### 6. Error Message System

```rust
// Instead of: "QUORUM_NOT_MET"
// Show: "Sistem sedang memproses workload Anda. Estimasi: 30-60 detik."

struct UserFriendlyError {
    code: ErrorCode,
    message_id: String,
    message_en: String,
    suggestion_id: Option<String>,
    suggestion_en: Option<String>,
    docs_link: Option<String>,
}
```

#### 7. CLI Improvements

```bash
# Simplified commands
dsdn deploy .                    # Deploy current directory
dsdn upload ./data --encrypt     # Upload with encryption
dsdn status                      # Show all deployments
dsdn logs <deployment>           # Stream logs
dsdn exec <deployment> -- bash   # Interactive shell

# Progress indicators
dsdn deploy .
# Building artifact...
# Uploading to DSDN...
# Scheduling workload...
# Waiting for nodes...
# Deployed! https://abc123.dsdn.id
```

#### 8. Playground / Web IDE

---

## Tahap 19 --- Receipt System v2 (Economic-Aware)

**Tujuan:** Mengintegrasikan sistem receipt dengan model ekonomi adaptif, fraud proof, dan deflasi terkontrol.

Chain Nusantara memverifikasi: threshold signature receipt (dari coordinator committee), node tidak self-dealing, node stake cukup, receipt belum terpakai, execution commitment valid, challenge period elapsed atau redundant execution passed.

### Receipt Flow

```
Storage Receipt:
  -> Immediate verification via merkle proof
  -> Reward distributed immediately

Compute Receipt (Standard):
  -> ExecutionCommitment verified
  -> Challenge period (1-4 hours)
  -> If no challenge -> reward distributed
  -> If challenge -> arbitration

Compute Receipt (Redundant):
  -> Multi-node execution
  -> Output consensus
  -> Immediate reward if consensus
  -> Arbitration if mismatch
```

### Distribusi Reward

- 70% --- node (storage / compute)
- 20% --- validator
- 10% --- treasury

### Catatan Ekonomi Penting

- Burn tidak bersifat fixed.
- Dana treasury menjadi input bagi modul deflasi adaptif (lihat Tahap 24).
- Pada fase bootstrap (RF = 3), burn dapat diminimalkan atau ditunda.
- Pada fase ekonomi normal, burn dilakukan secara berkala sesuai parameter on-chain.

Receipt disimpan di: LMDB (local), Celestia DA (global canonical log).

**Crates yang harus diubah / dilibatkan:** `chain`, `coordinator`, `proto`, `storage`, `node`, `validator`, `agent`, `ingress`, `fraud_proof`, `tss`.

> Receipt v2 pada tahap ini belum mengaktifkan ekonomi publik sepenuhnya. Adaptive logic tidak boleh diekspos ke pengguna, hanya diverifikasi secara internal. Receipt v2 tidak dianggap valid karena ditandatangani coordinator, melainkan karena konsistensinya dengan state yang direkonstruksi dari Data Availability log. Coordinator diperlakukan sebagai publisher receipt, bukan notaris terpercaya.

---

## Tahap 20 --- Bootstrap Governance Mode (Semi-Governance)

**Tujuan:** Mengaktifkan modul governance dalam mode bootstrap, di mana governance sudah berjalan secara teknis tetapi belum memiliki kewenangan penuh, sesuai dengan Progressive Governance Model (Fase 1).

### Karakteristik Governance Mode

- Governance aktif dalam non-binding mode.
- Foundation / Founder Authority memiliki hak override dan veto terbatas.
- Sistem tetap berjalan normal walau proposal governance tidak dieksekusi.

### Mekanisme yang Diaktifkan

Validator dapat: mengajukan proposal, melakukan voting.

Voting bersifat: advisory, tidak auto-execute.

Quadratic Voting komunitas: opsional, tidak mengikat.

### Governance Scope (Dibatasi)

- Diskusi perubahan fee (tanpa eksekusi otomatis).
- Simulasi Node Cost Index.
- Simulasi slashing rules.
- Simulasi compliance action (tanpa eksekusi).

### Batasan Penting

- Tidak ada perubahan parameter protokol tanpa persetujuan Foundation.
- Tidak ada slashing berbasis governance.
- Tidak ada compliance action final (hanya simulasi).

### Tujuan Fase Ini

- Menguji stabilitas modul governance.
- Menguji partisipasi validator.
- Melatih ekosistem sebelum desentralisasi penuh.

**Crates yang harus diubah / dilibatkan:** `chain`, `validator`, `agent`, `common`.

> Tidak ada UI governance publik, dashboard voting, atau call-to-action governance selama fase ini. Governance hanya dapat diakses melalui CLI internal validator.

---

## Tahap 21 --- Compliance Framework (No Data Access)

Validator hanya boleh: baca metadata, memblokir endpoint/pointer. Validator tidak boleh buka data (encrypted).

**Tambahan blueprint v0.5.2:** Validator tidak bisa delete chunk. Deletion hanya bisa dilakukan oleh user melalui User-Controlled Delete.

**Crates yang harus diubah / dilibatkan:** `validator`, `chain`, `coordinator`, `ingress`, `node`.

> Catatan: Tahap ini berjalan dalam Bootstrap / Transition Governance Mode, tanpa kewenangan governance penuh.

---

## Tahap 22 --- Geographic Routing (Zone + Class + Stake Aware)

Node dipilih berdasarkan: latensi terdekat, zona berbeda, stake weight, node class, anti-self-dealing.

Ingress harus baca: `node_registry_state` hasil rekonstruksi dari DA.

**Crates yang harus diubah / dilibatkan:** `coordinator`, `ingress`, `node`, `storage`, `chain`.

> Catatan: Tahap ini berjalan dalam Bootstrap / Transition Governance Mode, tanpa kewenangan governance penuh. Keputusan routing harus deterministik berdasarkan state hasil replay DA, dan tidak boleh bergantung pada keputusan imperatif coordinator.

---

## Tahap 23 --- Two-Class Config with Stake Validation

**Tambahan baru:**

Node reguler atau data center tidak aktif sebelum stake diverifikasi chain.

Jika stake turun karena slashing: node otomatis masuk mode "quarantined", coordinator tidak akan memilih node tersebut untuk workload.

**Crates yang harus diubah / dilibatkan:** `coordinator`, `chain`, `node`, `validator`, `ingress`.

> Catatan: Tahap ini berjalan dalam Bootstrap / Transition Governance Mode, tanpa kewenangan governance penuh.

---

## Tahap 24 --- Economic Model Adaptive (With Dynamic Fee + Treasury Burn)

**Tujuan:** Mengimplementasikan model ekonomi adaptif dan deflasi terkontrol sesuai whitepaper DSDN.

### Komponen Utama

#### 1. Node Cost Index (On-chain)

Node Cost Index dihitung dari sumber on-chain dan off-chain oracle terbatas: harga listrik rata-rata, biaya storage, bandwidth, beban jaringan (dari DA blob). Index ini menjadi dasar rekomendasi fee.

#### 2. Adaptive Fee Mechanism

Biaya layanan disesuaikan secara otomatis:

- `token_price` naik --- `base_fee` turun.
- `token_price` turun --- `base_fee` naik.

Penyesuaian dibatasi agar tidak terjadi shock biaya: maksimal +/-20% per periode penyesuaian.

#### 3. Adaptive Treasury Burn (Deflation Control)

Burn tidak bersifat fixed. Burn ditentukan oleh modul ekonomi dengan input: total volume usage jaringan, total fee masuk treasury, total supply beredar.

#### 4. Stable Fee Oracle

Lihat Tahap 24.2.

#### 5. Bootstrap Subsidy Program

Lihat Tahap 24.1.

### Target Deflasi Tahunan: 3--6%

**Aturan umum:**

- Pada fase bootstrap (RF = 3): burn minimal atau non-aktif.
- Pada fase transisi: burn rendah dan bertahap.
- Pada fase ekonomi normal: burn aktif untuk menjaga deflasi terkontrol.

Burn dilakukan melalui on-chain scheduled job dengan parameter yang dapat diaudit dan disesuaikan melalui governance pada fase lanjut.

**Crates yang harus diubah / dilibatkan:** `chain`, `coordinator`, `node`, `validator`, `common`.

> Selama tahap ini, seluruh mekanisme adaptif berjalan dalam mode simulasi (shadow mode) dan tidak boleh mempengaruhi harga publik, SLA, atau ekspektasi ekonomi pengguna. Model ekonomi adaptif pada tahap ini bersifat dormant / shadow mode, tidak dijadikan dasar harga publik sampai Tahap 31 berhasil.

---

## Tahap 24.1 --- Bootstrap Subsidy Program

**Tujuan:** Menyelesaikan bootstrap economics problem dengan subsidy program yang terstruktur untuk Year 1--2.

**Prinsip Penting:**

- Node harus bisa profitable dari Day 1.
- Subsidy menurun gradually seiring organic demand naik.
- Funded dari Bootstrap Subsidy Pool (revisi token allocation).
- Transparent dan auditable.

### Token Allocation Revisi

Sebelum: 60% Node dan Validator Reward Pool (20 tahun).

Sesudah: 50% Node dan Validator Reward Pool (20 tahun), 10% Bootstrap Subsidy Pool (3 tahun, front-loaded).

### Subsidy Mechanism

```rust
struct BootstrapSubsidy {
    // Target minimum revenue per node per month
    target_revenue_nusa: Amount,  // e.g., 500 NUSA

    // Subsidy rate (decreasing over time)
    subsidy_schedule: Vec<SubsidyPeriod>,

    // Eligibility criteria
    min_uptime_percent: u8,        // 95%
    min_storage_utilization: u8,   // 50%
    max_self_dealing_percent: u8,  // 0%
}

struct SubsidyPeriod {
    start_month: u8,
    end_month: u8,
    subsidy_percent: u8,  // % of target_revenue covered
}

// Example schedule:
// Month 1-6:   70% subsidy (Foundation covers 70% of target)
// Month 7-12:  50% subsidy
// Month 13-18: 30% subsidy
// Month 19-24: 15% subsidy
// Month 25+:   0% subsidy (pure organic)
```

### Subsidy Calculation

```rust
fn calculate_monthly_subsidy(
    node: &Node,
    organic_revenue: Amount,
    period: &SubsidyPeriod,
    config: &BootstrapSubsidy,
) -> Amount {
    if !is_eligible(node, config) {
        return Amount::zero();
    }

    let target = config.target_revenue_nusa;
    let shortfall = target.saturating_sub(organic_revenue);
    let subsidy = shortfall * period.subsidy_percent / 100;

    subsidy
}
```

### Eligibility Criteria

- Uptime >= 95% dalam period.
- Storage utilization >= 50%.
- Tidak ada self-dealing violation.
- Tidak ada slashing event.
- Valid stake maintained.

### Distribution

- Subsidy distributed monthly.
- Requires node to submit proof of metrics.
- Verified against DA logs.
- Distributed via chain transaction.

### Sunset Conditions

- Automatic sunset setelah Month 36.
- Early sunset jika organic demand > 80% of target.
- Governance dapat extend dalam kondisi darurat.

### Validasi Wajib

- Subsidy calculation correct.
- Eligibility check working.
- Distribution automated.
- Fraud detection active (fake metrics).

### Kriteria Selesai

- Subsidy calculation implemented.
- Eligibility verification working.
- Monthly distribution automated.
- Dashboard untuk node operators.

**Crates terlibat:** `chain`, `coordinator`, `node`, `common`.

---

## Tahap 24.2 --- Stable Fee Oracle Mechanism

**Tujuan:** Menghilangkan risiko token price volatility terhadap ekonomi jaringan dengan stable fee mechanism.

**Prinsip Penting:**

- Fee dihitung dalam USD-equivalent.
- Node cost dalam fiat, revenue harus stable dalam fiat terms.
- User tidak perlu worry tentang NUSA price untuk budgeting.
- Oracle decentralized dan resistant to manipulation.

### Arsitektur

```
+---------------------------------------------+
|           Price Oracle Aggregator            |
|                                              |
|  Sources:                                    |
|  - Chainlink (if available)                  |
|  - Pyth Network                              |
|  - DEX TWAP (NUSA/USDC)                      |
|  - Validator-submitted prices                |
|                                              |
|  Aggregation: Median of sources              |
|  Update frequency: Every 15 minutes          |
|  Staleness threshold: 1 hour                 |
+---------------------------------------------+
```

### Komponen

#### 1. Price Oracle Contract

```rust
struct PriceOracle {
    current_price_usd: FixedPoint,  // NUSA/USD
    last_update: Timestamp,
    sources: Vec<PriceSource>,
    staleness_threshold: Duration,
}

impl PriceOracle {
    fn get_price(&self) -> Result<FixedPoint> {
        if self.is_stale() {
            return Err(OracleError::StalePrice);
        }
        Ok(self.current_price_usd)
    }

    fn update_price(&mut self, submissions: Vec<PriceSubmission>) {
        // Take median of valid submissions
        let valid: Vec<_> = submissions
            .into_iter()
            .filter(|s| self.is_valid_source(&s.source))
            .collect();

        self.current_price_usd = median(&valid);
        self.last_update = now();
    }
}
```

#### 2. Fee Calculation (USD-based)

```rust
struct FeeCalculator {
    // Base fees in USD
    storage_per_gb_month_usd: FixedPoint,  // $0.10
    compute_per_minute_usd: FixedPoint,    // $0.05
    bandwidth_per_gb_usd: FixedPoint,      // $0.01
}

impl FeeCalculator {
    fn calculate_fee_nusa(
        &self,
        usage: &Usage,
        oracle: &PriceOracle,
    ) -> Result<Amount> {
        let fee_usd = self.calculate_fee_usd(usage);
        let nusa_price = oracle.get_price()?;
        let fee_nusa = fee_usd / nusa_price;

        // Apply bounds to prevent extreme volatility
        let fee_nusa = fee_nusa
            .max(self.min_fee_nusa)
            .min(self.max_fee_nusa);

        Ok(fee_nusa)
    }
}
```

#### 3. Fee Floor dan Ceiling

```rust
struct FeeBounds {
    // Even if NUSA moons, fee tidak turun di bawah ini
    min_fee_nusa: Amount,

    // Even if NUSA crash, fee tidak naik di atas ini
    max_fee_nusa: Amount,

    // Update bounds via governance
    last_governance_update: Timestamp,
}
```

#### 4. Validator Price Submission

```rust
// Validators submit price as part of their duty
struct ValidatorPriceSubmission {
    validator: ValidatorId,
    nusa_usd_price: FixedPoint,
    sources_used: Vec<String>,
    signature: Ed25519Signature,
    timestamp: Timestamp,
}
```

#### 5. Fallback Mechanism

```
# User melihat fee dalam USD terms
$ dsdn estimate --file ./data.csv

Estimated costs (monthly):
  Storage (100GB):  $10.00 (~200 NUSA)
  Bandwidth (50GB): $0.50 (~10 NUSA)
  Total:            $10.50 (~210 NUSA)

Note: NUSA amount may vary based on current price.
Current rate: 1 NUSA = $0.05
```

#### 6. Node Revenue Stability

```
# Node melihat revenue dalam USD terms
$ dsdn node stats --month december

Revenue this month:
  Storage fees:  $150.00 (earned 3,000 NUSA)
  Compute fees:  $50.00 (earned 1,000 NUSA)
  Total:         $200.00 (earned 4,000 NUSA)

Monthly costs (estimated):
  Server:        $100.00
  Bandwidth:     $30.00
  Total:         $130.00

Profit:          $70.00
```

### Validasi Wajib

- Oracle aggregation correct.
- Staleness detection working.
- Fee bounds enforced.
- User sees USD-equivalent pricing.

### Kriteria Selesai

- Price oracle deployed.
- Multiple sources integrated.
- Fee calculation uses oracle.
- Bounds prevent extreme volatility.
- User-facing USD pricing.

**Crates terlibat:** `chain`, `coordinator`, `agent`, `ingress`, `common`.

---

## Tahap 25 --- Security Hardening (With Stake-Slash Test)

**Tambahan:** Test node slashing untuk: liveness failure, data corruption, repeated malicious behavior, self-dealing attempt, compute fraud (proven via fraud proof), false fraud accusation (challenger slashing).

**Slashing amounts:**

- Liveness failure: 0.5% stake.
- Data corruption: 5% stake.
- Compute fraud: 10% stake.
- False accusation: 5% challenger bond.
- Repeated malicious: force unbond + 30 day ban.

Pastikan node receiving slashing: cannot provide workload, cannot receive reward, needs cooldown before rejoining.

**Crates yang harus diubah / dilibatkan:** `chain`, `validator`, `node`, `storage`, `coordinator`, `e2e_tests` (file in `crates/chain`).

---

## Tahap 26 --- Multi-Zone Self-Healing (With DA-Synchronized Placement)

Setiap self-heal event harus: dicatat sebagai blob DA, di-aplikasikan ulang oleh semua node.

**Tambahan:**

- Self-heal events harus posted ke active DA (Celestia atau fallback).
- Self-heal harus work regardless of which DA active.
- Recovery harus trigger setelah DA failover.

Dengan ini, zone layout akan konsisten seluruh jaringan.

**Crates yang harus diubah / dilibatkan:** `coordinator`, `storage`, `node`, `proto`, `chain`.

---

## Tahap 27 --- Performance Benchmark (With DA Cost Simulation)

**Tambahan:**

- Hitung cost post-to-Celestia DA.
- Hitung latency state reconstruction.

Test full end-to-end cost: Upload --- Chunk --- DA --- Receipt --- Claim --- Reward.

Benchmark juga memeriksa: stake-weight scheduling performance, anti-self-dealing overhead.

**Tambahan benchmark:**

- DA Fallback Performance: failover latency, recovery time, state consistency verification.
- Multi-Coordinator Performance: TSS signing latency, epoch rotation overhead, committee consensus time.
- Fraud Proof Performance: trace generation overhead, merkleization cost, challenge verification time, interactive game rounds.
- Oracle Performance: price update latency, aggregation accuracy, staleness handling.

**Benchmark targets:**

- DA failover: < 5 minutes.
- TSS signing: < 500ms.
- Trace generation: < 10% overhead.
- Oracle update: < 1 minute.
- Bootstrap performance: waktu dari fresh node start hingga pertama kali terhubung ke jaringan (target: < 30 detik dengan DNS seed available).
- PEX propagation time: waktu hingga seluruh jaringan test (10 node) saling mengenal (target: < 10 menit).
- peers.dat warm start time: waktu connect dari cache (target: < 5 detik).

**Crates yang harus diubah / dilibatkan:** `coordinator`, `storage`, `node`, `chain`, `agent`, `e2e_tests` (file in `crates/chain`).

> Benchmark difokuskan pada validasi determinisme, konsistensi, dan overhead trust model, bukan pada klaim performa komersial.

---

## Tahap 28 --- Mainnet Preparation (With Identity Verification)

**Tambahan:**

- KYC-light hanya untuk validator (karena governance authority).
- Node reguler tidak wajib KYC.

Pada genesis: stake requirement embed, multisig validator embed, slashing rules embed.

**Tambahan pada genesis:**

- DA fallback configuration.
- Coordinator committee initial members.
- TSS key ceremony results.
- Fraud proof parameters.
- Oracle initial sources.
- Bootstrap subsidy schedule.
- Fee bounds initial values.
- DNS seed domain(s) telah dibeli dan DNS A record aktif.
- Minimal 1 dedicated bootstrap node running 24/7.
- Bootstrap config default sudah terisi dengan DNS seed production.
- `peers.dat` path sudah di-set di production config.
- Full bootstrap test dari fresh node berhasil.

**Crates yang harus diubah / dilibatkan:** `chain`, `validator`, `coordinator`, `node`, `ingress`, `agent`.

> Mainnet pada tahap ini belum dianggap production public network, dan hanya dibuka untuk operator dan pilot terverifikasi. Mainnet pada tahap ini belum boleh dipresentasikan sebagai jaringan trustless, permissionless, atau censorship-resistant.

---

# Tahap 28.1 --- Bootstrap Network System (DNS Seed + Peer Discovery)

**Tujuan:** Mengimplementasikan sistem bootstrap jaringan DSDN berbasis DNS seed dan IP publik, mirip Bitcoin, agar seluruh komponen sistem (chain, node, coordinator, validator, ingress) dapat saling menemukan dan terhubung secara peer-to-peer tanpa hardcoded address. Tahap ini adalah **critical gate** sebelum mainnet launch --- gagal di bootstrap berarti gagal mainnet.

**Prinsip Penting:**

- Bootstrap hanya pintu masuk awal. Setelah node terhubung dan mendapat peer list, node mandiri.
- Tidak ada single point of failure. Seed DNS dan IP publik bersifat redundant dan fallback-chain.
- Founder, komunitas, dan operator bisa menambah seed kapan saja.
- File `peers.dat` menjadi persistent local cache agar node tidak selalu bergantung pada seed.
- Sistem harus toleran terhadap seed yang mati, expired, invalid, atau unreachable.
- Desain mengikuti model Bitcoin: DNS seed → peer exchange → local cache → self-sustaining network.

**Depends on:** Tahap 28 (Mainnet Preparation selesai, semua komponen infrastruktur sudah ready).

**Catatan Pre-Mainnet Wajib:** Founder harus membeli minimal 1 domain untuk DNS seed sebelum mainnet launch (contoh: `seed1.dsdn.network`). Domain tambahan sangat disarankan untuk redundansi. Pembelian domain dicatat sebagai checklist item di mainnet preparation.

---

## 28.1.A --- Bootstrap Config & Seed Registry Foundation

**Tujuan:** Membuat file `bootstrap_system.rs` di crate `common` yang berisi konfigurasi seed DNS, daftar IP publik statis, dan logic registry seed. File ini menjadi sumber kebenaran bootstrap untuk seluruh komponen DSDN.

### Kenapa di crate `common`?

Karena semua komponen DSDN (chain, node, coordinator, validator, ingress) membutuhkan bootstrap. Menaruh di `common` menghindari duplikasi dan menjamin konsistensi konfigurasi di seluruh sistem.

### File Baru: `crates/common/src/bootstrap_system.rs`

Isi modul ini mencakup:

#### 1. Seed DNS Config

Struct konfigurasi yang menyimpan daftar DNS seed. Saat ini dikosongkan karena domain belum dibeli, tetapi struct dan logic harus sudah lengkap.

Contoh format seed DNS yang akan diisi menjelang mainnet:
```
seed1.dsdn.network
seed2.dsdn.network
seed3.dsdn.network
```

Aturan seed DNS:
- Setiap seed DNS adalah domain yang di-resolve ke satu atau lebih IP address (A record / AAAA record).
- Satu seed bisa return banyak IP (round-robin DNS).
- Seed list bisa ditambah oleh founder, komunitas, atau operator melalui config file.
- Minimal 1 seed wajib ada untuk mainnet, direkomendasikan 3+.

#### 2. Static IP Registry

Daftar IP publik statis sebagai alternatif DNS seed. IP ini bisa dari:
- Node komunitas yang bersedia menjadi bootstrap node.
- Founder-operated seed node.
- Operator data center yang menyediakan entry point.

Format: `IP:Port` (contoh: `203.0.113.50:30303`).

Aturan IP statis:
- Bisa ditambah siapa saja melalui config file atau CLI.
- Bisa 0 (kosong) jika hanya mengandalkan DNS seed.
- Tidak ada batas jumlah (1, 2, 3, ... 50, bahkan lebih).
- IP yang invalid atau unreachable akan di-skip otomatis.

#### 3. Bootstrap Config File (`root_dsdn/dsdn.toml`)

Format konfigurasi yang bisa diedit user:
```toml
[bootstrap]
# DNS seeds (founder/community maintained)
dns_seeds = [
    # "seed1.dsdn.network",
    # "seed2.dsdn.network",
    # "seed3.dsdn.network",
]

# Static IP peers (community maintained)
static_peers = [
    # "203.0.113.50:30303",
    # "198.51.100.10:30303",
]

# Local peer cache
peers_file = "peers.dat"

# Connection settings
max_outbound_connections = 8
max_inbound_connections = 125
dns_resolve_timeout_secs = 10
peer_connect_timeout_secs = 5
```

#### 4. Seed Priority & Fallback Order

Implementasi urutan fallback yang jelas:
```
1. Coba peers dari peers.dat (local cache, paling cepat)
   -> Jika ada peer valid dan reachable -> gunakan
   -> Jika semua gagal atau peers.dat kosong -> lanjut ke 2

2. Coba static IP peers dari config
   -> Iterasi satu per satu
   -> Jika IP valid dan reachable -> gunakan, simpan ke peers.dat
   -> Jika IP tidak valid/unreachable -> skip, coba IP berikutnya
   -> Jika semua IP gagal -> lanjut ke 3

3. Coba DNS seeds dari config
   -> Resolve seed1 -> dapat IP list -> coba connect
   -> Jika seed1 gagal (DNS error, timeout, no A record) -> coba seed2
   -> Jika seed2 gagal -> coba seed3
   -> Dan seterusnya sampai seed terakhir
   -> Jika semua DNS seed gagal -> lanjut ke 4

4. Fallback: Kombinasi retry
   -> Retry semua sumber di atas dengan backoff
   -> Log warning bahwa tidak ada peer yang bisa dihubungi
   -> Node tetap hidup dan retry periodik (setiap 30 detik)
```

### Deliverables 28.1.A

1. File `crates/common/src/bootstrap_system.rs` dengan struct `BootstrapConfig`, `DnsSeed`, `StaticPeer`, `SeedRegistry`.
2. Parser untuk bootstrap config (dari `bootstrap.toml` atau section di `dsdn.toml`).
3. DNS resolver wrapper yang async, timeout-aware, dan error-tolerant.
4. Fallback chain logic (peers.dat → static IP → DNS seed → retry).
5. Unit test: config parsing, DNS resolve mock, fallback ordering, invalid seed handling.

### Crates Terlibat

`common`

### Kriteria Selesai

- `BootstrapConfig` bisa di-load dari file config.
- DNS seed list bisa kosong (valid untuk development, invalid untuk mainnet).
- Static IP list bisa kosong.
- Fallback chain logic ter-test dengan semua kombinasi: semua sumber gagal, hanya DNS works, hanya IP works, hanya peers.dat works, semua works.

---

## 28.1.B --- Peer Discovery, Exchange & Local Cache (peers.dat)

**Tujuan:** Mengimplementasikan peer discovery melalui DNS resolve dan IP connect, peer exchange protocol antar node, dan persistent local cache `peers.dat` agar node bisa bootstrap tanpa DNS setelah pernah terhubung.

**Depends on:** 28.1.A (BootstrapConfig dan SeedRegistry ready)

### 1. DNS Seed Resolution

Proses resolve DNS seed menjadi IP address:

```
dns_seed "seed1.dsdn.network"
-> DNS A record query
-> returns: [203.0.113.50, 203.0.113.51, 198.51.100.10]
-> shuffle (randomize order untuk load distribution)
-> coba connect satu per satu
-> yang berhasil connect -> masuk ke active peers
```

Aturan resolve:
- Timeout per DNS query: configurable (default 10 detik).
- Jika DNS return 0 IP -> seed dianggap gagal, lanjut ke seed berikutnya.
- Jika DNS return IP tapi semua unreachable -> seed dianggap partially failed, log warning.
- Support IPv4 (A record) dan IPv6 (AAAA record).
- Randomize hasil resolve agar tidak semua node connect ke IP yang sama.

### 2. Peer Connection & Handshake

Setelah mendapat IP dari DNS/static/peers.dat, node melakukan:

```
1. TCP connect ke IP:Port
2. Handshake:
   - Kirim: protocol_version, network_id (mainnet/testnet), node_id, listen_port
   - Terima: protocol_version, network_id, node_id, listen_port
   - Validasi: network_id harus sama, protocol_version compatible
3. Jika handshake sukses -> peer dianggap valid
4. Jika handshake gagal -> disconnect, coba peer berikutnya
```

Network ID penting untuk isolasi:
- `mainnet` → hanya connect ke mainnet peer.
- `testnet` → hanya connect ke testnet peer.
- Mismatch → reject handshake.

### 3. Peer Exchange Protocol (PEX)

Setelah terhubung ke minimal 1 peer, node bisa minta peer list dari peer yang sudah terkoneksi:

```
Node A -> Node B: "GetPeers" request
Node B -> Node A: response berisi list peer yang Node B ketahui (max 1000 entries)
Node A: filter, validate, coba connect ke peer baru
```

Aturan PEX:
- Peer hanya share peer yang pernah berhasil di-connect dalam 24 jam terakhir (bukan dead peer).
- Response di-limit (max 1000 peer per response) untuk anti-spam.
- Node tidak boleh share peer yang sudah di-ban.
- PEX request di-rate-limit (max 1 request per peer per 15 menit).

### 4. peers.dat --- Persistent Peer Cache

File `peers.dat` menyimpan peer yang pernah berhasil di-contact, agar node bisa bootstrap cepat tanpa DNS resolve.

Isi peers.dat per entry:
```
- IP address (IPv4 atau IPv6)
- Port
- Node ID (Ed25519 public key)
- Last seen timestamp
- Last successful connect timestamp
- Connection success count
- Connection failure count
- Source (dns_seed / static_config / peer_exchange / inbound)
- Network ID (mainnet / testnet)
```

Aturan peers.dat:
- Disimpan sebagai binary file (compact, cepat baca/tulis) atau JSON (debug-friendly). Pilih satu, konsisten.
- Max entries: 10.000 (cukup untuk jaringan besar, tidak terlalu berat di disk).
- Entries yang tidak pernah berhasil connect dalam 30 hari -> otomatis dihapus (garbage collection).
- Entries yang gagal connect 10x berturut-turut -> ditandai sebagai "suspicious", prioritas rendah.
- peers.dat di-write secara atomik (write ke temp file, lalu rename) untuk mencegah corruption.
- Saat startup, peers.dat di-load dan peer diurutkan berdasarkan: last successful connect (terbaru duluan).

### 5. Peer Scoring & Selection

Tidak semua peer sama baiknya. Sistem scoring sederhana:

```
score = base_score
      + (success_count * 2)
      - (failure_count * 3)
      + recency_bonus (peer terakhir connect < 1 jam: +10, < 24 jam: +5)
      - staleness_penalty (peer terakhir connect > 7 hari: -5, > 30 hari: -10)
```

Node prioritaskan connect ke peer dengan score tertinggi.

### 6. Peer Rotation & Refresh

Node yang sudah berjalan lama harus tetap menemukan peer baru:
- Setiap 30 menit: lakukan 1 DNS seed resolve random untuk menemukan peer baru.
- Setiap 15 menit: lakukan PEX request ke 1 random connected peer.
- Setiap 1 jam: coba connect ke 2 peer random dari peers.dat yang belum terkoneksi.
- Ini mencegah network fragmentation dan menjaga connectivity.

### Deliverables 28.1.B

1. DNS seed resolver (async, timeout, multi-seed fallback, IPv4+IPv6).
2. Peer handshake protocol (version check, network ID validation).
3. Peer Exchange Protocol (PEX) — request/response, rate limiting, filtering.
4. `peers.dat` read/write/garbage-collection logic.
5. Peer scoring dan selection algorithm.
6. Peer rotation dan periodic refresh background task.
7. Unit test: DNS resolve mock, handshake success/failure, PEX filtering, peers.dat read/write/GC, scoring logic.
8. Integration test: 3 node bootstrap dari 1 DNS seed, lalu PEX sampai semua saling kenal.

### Crates Terlibat

`common`, `node`, `proto` (untuk handshake dan PEX message definitions)

### Kriteria Selesai

- Node bisa bootstrap dari DNS seed, mendapat peer, dan menyimpan ke peers.dat.
- Node restart → langsung connect dari peers.dat tanpa DNS resolve.
- PEX bekerja: node A kenal node B, node B kenal node C, setelah PEX node A kenal node C.
- peers.dat garbage collection bekerja (dead peer dihapus setelah 30 hari).
- Fallback chain fully functional: peers.dat → static IP → DNS seed.
- Peer scoring mengutamakan peer yang reliable.

---

## 28.1.C --- Full System P2P Integration & Network Resilience

**Tujuan:** Mengintegrasikan bootstrap system ke seluruh komponen DSDN (chain, node, coordinator, validator, ingress) sehingga semua bisa saling menemukan melalui P2P, dan memastikan jaringan resilient terhadap berbagai failure scenario.

**Depends on:** 28.1.A (config), 28.1.B (discovery & peers.dat)

### 1. Integrasi ke Setiap Komponen DSDN

Setiap komponen yang butuh jaringan harus menggunakan bootstrap system:

#### Chain Node
- Saat startup, chain node menggunakan `BootstrapConfig` untuk menemukan peer chain lainnya.
- Setelah terhubung, chain node melakukan block sync dan state sync dari peer.
- Chain node mengiklankan dirinya ke peer lain agar bisa ditemukan.
- Chain node menyimpan peer ke peers.dat.

#### Storage Node
- Storage node bootstrap untuk menemukan coordinator dan chain node.
- Setelah terhubung ke coordinator (via peer discovery, bukan hardcoded address), node register diri.
- Storage node juga menyimpan peer storage node lain untuk data replication.

#### Coordinator
- Coordinator bootstrap untuk menemukan chain node (untuk stake verification) dan storage node.
- Coordinator committee members menemukan satu sama lain via bootstrap (critical untuk TSS/FROST).
- Coordinator mengiklankan dirinya sebagai discoverable service type.

#### Validator
- Validator bootstrap untuk menemukan chain node dan coordinator.
- Validator harus bisa menemukan semua validator lain untuk consensus.

#### Ingress
- Ingress bootstrap untuk menemukan coordinator dan storage node terdekat.
- Ingress node mengiklankan dirinya untuk load balancing.

### 2. Service Discovery via Peer Advertisement

Setiap node mengiklankan "service type" saat handshake:

```
ServiceType:
  - Chain         (block production, state)
  - Storage       (data storage node - reguler)
  - StorageDC     (data storage node - data center)
  - Coordinator   (workload coordination)
  - Validator     (consensus & validation)
  - Ingress       (HTTP gateway)
  - Bootstrap     (dedicated bootstrap node, no other function)
```

Saat node melakukan PEX, peer juga menyertakan service type. Ini memungkinkan node untuk menemukan komponen spesifik yang dibutuhkan. Misal: validator hanya perlu menemukan chain node dan coordinator, tidak perlu connect ke semua storage node.

### 3. Bootstrap Node (Dedicated)

Founder dan komunitas bisa menjalankan dedicated bootstrap node yang hanya melayani peer discovery:

- Tidak menyimpan data.
- Tidak ikut consensus.
- Hanya melayani handshake, PEX, dan menjadi entry point jaringan.
- Resource requirement sangat rendah (bisa berjalan di VPS kecil).
- DNS seed biasanya mengarah ke bootstrap node ini.

Cara menjalankan:
```bash
dsdn-node --mode bootstrap --listen 0.0.0.0:30303 --network mainnet
```

### 4. Network Partition Recovery

Jika jaringan mengalami partisi (sebagian node terisolasi):

```
Deteksi:
- Node mendeteksi jumlah connected peer turun drastis (di bawah min_peers threshold).
- Node mendeteksi tidak menerima block/event baru dalam waktu lama.

Recovery:
1. Aggressive DNS seed resolve (semua seed, bukan hanya 1).
2. Retry semua peer di peers.dat.
3. Retry semua static IP.
4. Jika masih gagal: log critical alert, terus retry dengan exponential backoff.
```

### 5. Seed Infrastructure Checklist (Pre-Mainnet)

Sebelum mainnet launch, founder WAJIB menyelesaikan:

```
[ ] Beli minimal 1 domain untuk DNS seed (contoh: seed1.dsdn.network)
[ ] Setup DNS A record mengarah ke bootstrap node IP
[ ] Bootstrap node running 24/7 di VPS/server dedicated
[ ] Test DNS resolve dari berbagai lokasi geografis
[ ] (Disarankan) Beli 2 domain tambahan untuk redundansi
[ ] (Disarankan) Setup bootstrap node di 2-3 lokasi berbeda (geo-distributed)
[ ] (Disarankan) Minta 2-3 komunitas/operator menjalankan bootstrap node tambahan
[ ] (Disarankan) Tambahkan 3-5 static IP dari operator terpercaya ke default config
[ ] Test full bootstrap: fresh node → DNS resolve → connect → PEX → fully synced
[ ] Test fallback: matikan seed1 → pastikan failover ke seed2 bekerja
[ ] Test peers.dat: restart node → pastikan connect tanpa DNS
[ ] Document seed maintenance procedure (domain renewal, IP update, etc.)
```

### 6. Anti-Abuse & Security

Bootstrap system bisa menjadi target attack. Proteksi:

- **DNS Poisoning:** Node harus verify peer setelah connect (handshake dengan network_id check, node_id verification). DNS hanya memberikan IP, bukan trust.
- **Eclipse Attack:** Node harus connect ke peer dari BERBAGAI sumber (DNS seed, static IP, PEX). Jangan bergantung pada satu sumber saja. Enforce: minimal N% peer harus dari sumber berbeda.
- **Sybil via PEX:** Rate limit PEX, jangan langsung trust semua peer dari PEX. Score peer berdasarkan behavior, bukan hanya availability.
- **Spam Connection:** Rate limit inbound connection per IP. Max N connection attempt per IP per menit.
- **peers.dat Poisoning:** Jika node terkoneksi ke banyak malicious peer yang memberikan fake peer list, peers.dat bisa tercemar. Mitigasi: scoring yang mengutamakan peer dengan successful block/data exchange, bukan hanya successful handshake.

### 7. Agent CLI Support

Agent mendapat command baru untuk manajemen bootstrap:

```bash
# Lihat status peer
dsdn-agent peers list

# Tambah static peer manual
dsdn-agent peers add 203.0.113.50:30303

# Tambah DNS seed manual
dsdn-agent peers add-seed seed4.dsdn.network

# Lihat peers.dat stats
dsdn-agent peers stats

# Force re-bootstrap (clear peers.dat, mulai dari DNS seed)
dsdn-agent peers reset

# Lihat peer berdasarkan service type
dsdn-agent peers list --type coordinator
dsdn-agent peers list --type chain
```

### 8. Monitoring & Observability

Metrics yang harus di-expose:

- `bootstrap_dns_resolve_total` — jumlah DNS resolve attempts.
- `bootstrap_dns_resolve_success` — jumlah DNS resolve sukses.
- `bootstrap_dns_resolve_latency_ms` — latency DNS resolve.
- `bootstrap_peer_connect_total` — jumlah connection attempts.
- `bootstrap_peer_connect_success` — jumlah connection sukses.
- `bootstrap_peer_handshake_failure` — jumlah handshake gagal (breakdown by reason).
- `bootstrap_peers_dat_size` — jumlah entry di peers.dat.
- `bootstrap_active_peers` — jumlah peer yang saat ini terkoneksi.
- `bootstrap_active_peers_by_type` — breakdown per service type.
- `bootstrap_pex_requests_total` — jumlah PEX request sent/received.
- `bootstrap_fallback_triggered` — jumlah kali fallback dari satu sumber ke sumber lain.

### Integration Test Scenarios

1. **Fresh node, DNS only:** Node baru start dengan peers.dat kosong, hanya punya DNS seed → berhasil bootstrap, connect ke jaringan, sync state.
2. **Fresh node, static IP only:** DNS seed dikosongkan, hanya static IP → berhasil bootstrap.
3. **Warm restart:** Node punya peers.dat dari sesi sebelumnya → langsung connect tanpa DNS resolve.
4. **DNS seed down:** Seed 1 dan 2 mati → fallback ke seed 3 → berhasil bootstrap.
5. **Semua DNS seed down:** Semua DNS gagal → fallback ke static IP → berhasil bootstrap.
6. **Semua sumber down:** DNS, static IP, peers.dat semua gagal → node retry dengan backoff, log critical → saat satu sumber kembali hidup, node berhasil connect.
7. **Network partition recovery:** 2 group node terisolasi → satu node dari masing-masing group resolve DNS seed yang sama → kedua group reconnect.
8. **PEX propagation:** 10 node, hanya node 1 yang kenal DNS seed. Setelah PEX rounds, semua 10 node saling kenal.
9. **Service type discovery:** Validator berhasil menemukan coordinator dan chain node melalui PEX service type filter.
10. **Eclipse attack resistance:** Node yang menerima peer hanya dari 1 sumber → system warning. Node dipaksa diversify sumber.
11. **Multi-component bootstrap:** Chain node, storage node, coordinator, validator, ingress — semua start simultaneously dari bootstrap → semua saling menemukan dan beroperasi normal.
12. **peers.dat corruption:** File peers.dat corrupt/deleted → node fallback ke DNS seed dan static IP, rebuild peers.dat dari awal.

### Deliverables 28.1.C

1. Integrasi `BootstrapConfig` ke semua komponen: chain, node, coordinator, validator, ingress.
2. Service type advertisement dalam handshake dan PEX.
3. Dedicated bootstrap node mode (`--mode bootstrap`).
4. Network partition detection dan recovery logic.
5. Anti-abuse: rate limiting, eclipse attack mitigation, peers.dat poisoning protection.
6. Agent CLI commands untuk manajemen peer dan seed.
7. Monitoring metrics untuk observability.
8. Seed infrastructure checklist document.
9. Full integration test suite (12 scenarios di atas).
10. End-to-end test: seluruh komponen DSDN bootstrap dari nol, saling menemukan, dan beroperasi normal.

### Crates Terlibat

`common`, `chain`, `node`, `coordinator`, `validator`, `ingress`, `agent`, `proto`

### Kriteria Selesai

- Semua komponen DSDN bisa bootstrap dan saling menemukan tanpa hardcoded address.
- Fallback chain bekerja di semua failure combination.
- peers.dat terbukti mempercepat restart (connect < 5 detik dari cache).
- PEX menyebarkan peer knowledge ke seluruh jaringan dalam < 10 menit.
- Service type discovery memungkinkan komponen menemukan komponen lain yang dibutuhkan.
- Anti-abuse protection active dan tested.
- Semua 12 integration test pass.
- Monitoring metrics visible di dashboard.
- Seed infrastructure checklist siap untuk mainnet.

---


## Ringkasan Dependency

```
28.1.A (Config & Seed Registry)
  ↓
28.1.B (Discovery, PEX, peers.dat)
  ↓
28.1.C (Full System Integration & Resilience)
  ↓
Tahap 29 (Mainnet Launch) — semua komponen DSDN fully P2P
```

**28.1.A** → Data layer. Config, struct, DNS resolver, fallback logic. Bisa dikerjakan independen.

**28.1.B** → Network layer. Discovery, handshake, PEX, peers.dat. Depends on 28.1.A.

**28.1.C** → Integration layer. Menyambungkan ke seluruh komponen DSDN + security + monitoring. Depends on 28.1.A + 28.1.B. Tahap paling berat dan paling critical karena melibatkan seluruh crates.

**Estimasi effort:** 28.1.A (20%), 28.1.B (35%), 28.1.C (45%).

**Crates total yang terlibat:** `common`, `chain`, `node`, `coordinator`, `validator`, `ingress`, `agent`, `proto`.

---

## Tahap 29 --- Mainnet Launch (Limited / Pilot Mainnet)

**Launch Dashboard untuk:**

- Node stake status.
- DA sync status (Celestia + fallback).
- Coordinator committee status.
- Reward distribution.
- Fraud proof challenges active.
- Oracle price feeds.
- Subsidy program status.
- Governance proposal status.

**Pilot Mainnet Characteristics:**

- Limited to verified operators.
- Bootstrap subsidy active.
- Fraud proof challenge period: conservative (4 hours).
- DA fallback: tested but not publicly advertised.
- Oracle: limited sources, governance backup.

**Crates yang harus diubah / dilibatkan:** `chain`, `coordinator`, `node`, `validator`, `ingress`, `agent`.

> Tidak diperbolehkan klaim "desentralisasi penuh", "trustless", atau "production-ready" dalam komunikasi eksternal.

---

## Tahap 30 --- Post-Mainnet Evolution

**Tambahan dari blueprint:**

- ZK receipts.
- Stake-weighted erasure coding placement.
- QUIC transport runtime.
- Federated learning on encrypted data.
- GPU virtualization for node DC.

**Evolusi lanjutan:**

- ZK Fraud Proof: Replace interactive game dengan ZK proof, instant verification, no challenge period, significant UX improvement.
- TEE Integration: SGX/SEV-SNP attestation, bypass fraud proof untuk attested compute, premium pricing untuk guaranteed execution.
- Multi-DA Expansion: EigenDA integration, Avail integration, cross-DA state verification.
- Advanced Oracle: More DEX integrations, cross-chain price feeds, prediction market integration.
- Anchor Tenant Program: Enterprise partnership framework, SLA guarantees, dedicated capacity reservation.

**Crates yang harus diubah / dilibatkan:** `runtime_wasm`, `runtime_vm`, `node`, `coordinator`, `storage`, `chain`, `common`, `fraud_proof`, `tss`.

> Mainnet ini tidak disertai kampanye publik, tidak ada open onboarding user umum.

---

## Non-Development Phases

---

## Tahap 31 --- Onboarding Pilot dan Enterprise (Rework)

**Tujuan:** Dapatkan 5--10 pilot terverifikasi; semua pilot bersifat non-mission-critical dan berfokus pada storage + batch/serving compute.

**Ruang lingkup:** Internal / private pilots only. Tidak ada PR publik, tidak ada case study publik sampai exit gate terpenuhi.

### Langkah Konkret

1. Definisikan paket pilot standar (scope minimal, diskon, SLA ringan internal only, support on-call, exit clauses).
2. Siapkan onboarding artefak: Terraform/Ansible playbook, agent image, S3-compat gateway sample, dan 1 contoh pipeline inferensi sederhana.
3. Rekrut pilot target: 1 kampus / lab R&D, 1 AI startup (non-mission critical), 1 organisasi backup/archival. Kontrak pilot tertulis (scope, metrik, data handling).
4. Jalankan onboarding checklist per pilot: identity --- key management --- upload encrypted data --- run 1 compute job --- verify receipts + rewards flow.
5. Sediakan dedicated support channel dan weekly feedback loop.

### Gate Masuk

Tahap 14A/14B (DA replay dan stake gating) dan Tahap 15 (logging WORM + DA mirror) harus lulus. Infrastruktur observability minimal harus hidup.

### Exit Criteria

- >= 3 pilot aktif (minimal) dengan bukti transaksi nyata (upload + compute) dan feedback loop terisi.
- Setiap pilot: >= 100 GB stored ter-enkripsi atau >= 1000 inference minutes total untuk jaringan (aturan alternatif: salah satu terpenuhi).
- DA replay test: restart coordinator/node --- state identik.
- Support runbook tersedia dan person on-call.

### Risiko dan Mitigasi

- **Risiko:** Pilot mengalami outage --- menurunkan kepercayaan. **Mitigasi:** Batasi pilot non-mission critical; kontrak exit dan rollback; warm standby replicas.
- **Risiko:** Eksposur publik sebelum siap. **Mitigasi:** Semua materi pilot bersifat NDA/internal sampai exit criteria tercapai.

---

## Tahap 32 --- SDK dan Developer Experience (DX) --- Prioritas Utama

**Tujuan:** Hilangkan friction developer sehingga integrasi terasa "biasa" (bukan Web3).

**Ruang lingkup:** Publik (developer) --- namun komunikasikan sebagai "developer beta" / closed signup.

### Langkah Konkret (Urutan Wajib)

1. Rilis SDK minimal: JS/TS (browser + Node), Python, Rust CLI. Sertakan S3-compat adapter dan Wasm deploy CLI.
2. Publish 10 contoh siap jalan: static site upload, backup client, simple model inference, worker cron. Sertakan CI template.
3. Integrasi auth OIDC + token credential flow untuk developer (simple onboarding).
4. Playground sandbox (non-production) untuk testing integrasi tanpa token ekonomi nyata.

### Gate Masuk

T31 pilot running dengan 1 pilot yang sudah mengintegrasikan SDK internal. DA replay + ingress health OK.

### Exit Criteria

- >= 100 dev signups pada daftar tunggu (closed beta) dan >= 50 repos aktif yang memakai SDK (indikator integrasi nyata).
- Error rate integrasi < X (ditentukan runbook) dan dokumentasi end-to-end tersedia.

### Risiko dan Mitigasi

- **Risiko:** SDK buggy --- developer drop off. **Mitigasi:** Aggressive CI, API stability contract, example apps, dev support channel.

---

## Tahap 33 --- Marketplace: Mode Internal / Operator-Only

> Revisi penting --- jangan publikasikan sebagai public marketplace dulu.

**Tujuan:** Sediakan mekanisme orderbook dan matching untuk internal resource discovery (DC operator dan internal demand), bukan public spot market.

### Langkah Konkret

1. Implementasi on-chain orderbook minimal (schema sederhana) + off-chain matching di coordinator (matching logic internal).
2. UI/CLI hanya untuk operator verified; publik tidak bisa melihat orderbook.
3. Reputation dan pricing discovery di dalam private dashboard.
4. Settlement via Chain receipts (v1) --- receipt flow harus kuat sebelum exposure.

### Gate Masuk

T32 (SDK) lulus; minimal 3 DC nodes dan >= 3 pilot customers aktif; receipts v1 teruji.

### Exit Criteria

- Marketplace internal: >= 500 offers posted dan >= 200 accepted orders internal / per measurement cycle (measurement cycle = defined operational metric period).
- Repeat customers: minimal 5 customers melakukan repeat orders.
- Operational KPIs: scheduler latency dan match latency harus memenuhi SLO yang diset.

### Risiko dan Mitigasi

- **Risiko:** Liquidity rendah --- gagal pasar publik. **Mitigasi:** Biarkan marketplace internal dulu; sediakan incentives grants untuk operator verified sebelum publis.

---

## Tahap 34 --- Managed Service dan SLA Tiers (Soft Launch)

**Tujuan:** Produk komersial berbayar tapi terbatas; validasi revenue model dengan 1--2 pelanggan yang sadar eksperimental.

**Ruang lingkup:** Komersial terbatas (select customers), tidak mass market.

### Langkah Konkret

1. Build managed control plane (dashboard read-only untuk customers + billing events ingestion).
2. Tawarkan SLA ringan (Gold/Silver/Bronze) hanya untuk managed customers: availability guarantees, RPO/RTO ringkas. Semua SLA internal dan kontrak pilot.
3. Operasional: define runbook, incident management, escalation.
4. Billing credits dan invoicing (fiat dan $NUSA accounting) --- awalnya invoice manual.

### Gate Masuk

Marketplace internal stabil; observability dan support on-call matured; legal DPA draft ready.

### Exit Criteria

- 2 paying managed customers (pilot --- paid with basic SLA).
- MRR pertama tercatat dan invoicing process berjalan.

### Risiko dan Mitigasi

- **Risiko:** Underpricing atau SLA breach. **Mitigasi:** Mulai SLA konservatif; impose maintenance windows; require customer backup plan.

---

## Tahap 35 --- Performance dan Cost Optimizations (Produk Level)

**Tujuan:** Turunkan latency dan cost sebelum skala publik.

### Langkah Konkret

1. Implement stake-weighted erasure coding placement (uji di staging).
2. Optimasi chunk size, caching, edge warm caches / CDN-like layer.
3. P99 latency dan cost per GB profiling dan tuning.

### Gate Masuk

2 paying managed customers + marketplace internal active.

### Exit Criteria

- P99 latency turun target (mis. >30% improvement relative baseline).
- Cost per GB turun target (mis. >20% improvement).
- Benchmarking dan DA cost simulation terjalankan.

### Risiko dan Mitigasi

- **Risiko:** Optimisasi menyebabkan kompleksitas operasional. **Mitigasi:** Feature flags, A/B test, rollback plan.

---

## Tahap 36 --- Compute Marketplace dan Model Hub (Publikasi Terbatas)

**Tujuan:** Buka marketplace compute dan model hub ke publik hanya jika demand dan infra sudah terbukti.

### Langkah Konkret

1. Model Hub metadata on-chain/DA + artifact stored di storage layer.
2. Compute job marketplace untuk inference: buyer submits job --- internal matching --- receipt settlement.
3. Metering (`runtime_usage_proof`) dan billing pipeline harus 100% auditable.

### Gate Masuk

- Marketplace internal KPI terpenuhi (exit criteria T33).
- Performance dan cost targets T35 terpenuhi.
- SDK dan DX bagus (T32).
- Security dan privacy baseline (T39) berjalan.

### Exit Criteria

- 50 models published dan >= 10k inference calls / month (real usage metrics).
- Revenue per inference > break-even.

### Risiko dan Mitigasi

- **Risiko:** Abuse / self-dealing. **Mitigasi:** Enforce anti-self-dealing checks, reputation penalties, slashing for proven abuse.

---

## Tahap 37 --- Privacy dan Trust Features (Opt-in, Enterprise)

**Tujuan:** Unlock enterprise adoption dengan TEE / MPC / ZK POC --- opt-in untuk node DC.

### Langkah Konkret

1. R&D dan POC SGX/SEV-SNP deployment for enclaves in selected DCs.
2. MPC/secret-sharing pipelines for parameter server / federated learning.
3. ZK-receipt prototyping (privacy-preserving audit trail).

### Gate Masuk

At least 1 managed customer requests privacy SLA; legal team greenlight for enclave usage.

### Exit Criteria

- 2 TEE-enabled DCs operational; 1 MPC PoC validated; enterprise sign-off.

### Risiko dan Mitigasi

- **Risiko:** TEE complexities + supply chain trust. **Mitigasi:** Limit to verified partners; continuous auditing; fallback to encrypted compute.

---

## Tahap 38 --- Interoperability (S3/IPFS/OCI)

**Tujuan:** Mudahkan migrasi dan integrasi ekosistem --- bukti fungsional bukan promosi besar.

### Langkah Konkret

1. S3-compatible gateway dan rclone/terraform provider tests.
2. IPFS/Arweave import/export utilities.
3. OCI registry support untuk container/model artifacts.

### Gate Masuk

Storage dan ingress stable, SDK integrations validated.

### Exit Criteria

- 3 third-party tools tested + integration docs.

### Risiko dan Mitigasi

- **Risiko:** Surface area attack via bridges. **Mitigasi:** Harden gateways, audit bridge code, rate limiting.

---

## Tahap 39 --- Compliance dan Certification (Legal Readiness)

**Tujuan:** Siapkan bukti dan dokumentasi agar enterprise/regulator nyaman --- jangan publish dulu.

### Langkah Konkret

1. Third-party pentest + code audit.
2. Prepare ISO27001 mapping, DPA templates, local legal counsel review.
3. On-prem connector blueprint (for hybrid customers).

### Gate Masuk

Managed customers + privacy features basic ready.

### Exit Criteria

- Pass one major security audit; DPA template accepted by >= 2 partners.

### Risiko dan Mitigasi

- **Risiko:** Overcommit compliance scope. **Mitigasi:** Phased compliance: start with security posture, then certs.

---

## Tahap 40 --- Node Operator Program dan Ecosystem Incentives

**Tujuan:** Skala kapasitas lewat operator terverifikasi, bukan open crowd.

### Langkah Konkret

1. Create operator certification test suite + badge.
2. Grants / onboarding incentives for early DC operators.
3. "Verified partner" program for resellers/integrators.

### Gate Masuk

Compliance baseline + managed service ops playbook.

### Exit Criteria

- 100 certified operators; 30 DC nodes onboarded (verified partners).

### Risiko dan Mitigasi

- **Risiko:** Rapid growth tanpa ops readiness. **Mitigasi:** Controlled onboarding batch, automated test harness.

---

## Tahap 41 --- Long-term R&D (GPU Virtualization, ZK Receipts, Satellite Nodes)

**Tujuan:** Jaga keunikan 5--10 tahun ke depan. R&D non-blocking produk saat ini.

### Langkah Konkret

Prototype GPU virtualization, ZK receipts PoC, satellite feasibility. R&D terpisah, funding via grants.

### Gate Masuk

Stabilitas ekonomi dan operator network (T40).

### Exit Criteria

- PoC berfungsi dan roadmap integrasi.

### Risiko dan Mitigasi

- **Risiko:** R&D cost. **Mitigasi:** Grant funding dan research partnerships.

---

## Tahap 42 --- Global Scale dan Partnership Push (Delegated / Later)

**Tujuan:** Ekspansi terkontrol regionally (ASEAN awal). Hanya aktif jika produk matang.

### Langkah Konkret

Partner with telco/local DCs, local legal counsel, CDN partners for hot caches.

### Gate Masuk

All prior gates for production readiness + compliance passed.

### Exit Criteria

- Operasi di 3 negara dan sustainable revenue.

### Risiko dan Mitigasi

- **Risiko:** Regulator risk. **Mitigasi:** Local partners + legal counsel.

---

## Operasional dan Tokenomics (Lintas Tahap --- Aturan Revisi)

- **Treasury dan pilot grants:** Gunakan untuk bootstrap internal marketplace dan operator subsidies --- jangan dipakai untuk memancing hype publik.
- **Billing dan credits:** For pilots/managed customers start with fiat invoicing + internal $credit accounting; exposure token economics hanya ketika marketplace publik dibuka.
- **Monitoring dan SLOs:** Status pages tetap internal sampai T34 exit. Publik status page hanya setelah managed customers dan marketplace minimal stabil.
- **Community dan grants:** Fokus dev grants untuk SDK adapters, bukan promosi marketplace.

---

## Komunikasi Publik --- Aturan Ketat

- **Sebelum T31 exit terpenuhi:** Publik only sees "DSDN sedang dalam private pilot / beta; fokus: secure storage dan compute." Jangan publish marketplace roadmap.
- **Governance UI/visibility:** Hidden sampai transition governance mode aktif (Fase 2/3 per whitepaper). Dashboard publik menampilkan hanya health, storage usage aggregate, dan status tanpa governance controls.
- **Case studies / press:** Hanya setelah managed customers bersedia dan KPI tercapai.