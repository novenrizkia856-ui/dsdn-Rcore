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
    node-1 "$DA_RPC_URL" ./data/node1 45831 &
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
cargo run -p dsdn-node --bin dsdn-node -- node-1 mock ./data/node1 45831

# Option 2: Environment variables (production)
export DA_RPC_URL=http://localhost:26658
export DA_AUTH_TOKEN=xxx
export DA_NAMESPACE=xxx
cargo run -p dsdn-node --bin dsdn-node -- node-1 env ./data/node1 45831

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

**a Epoch Management**

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

> **Catatan Penting (FIX #4):** Challenge period pada tahap ini bersifat **timer-only**. Receipt compute akan auto-finalize setelah challenge window habis tanpa kemungkinan challenge apapun. Actual fraud proof submission dan verification diimplementasi di Tahap 18.8. Node dan chain cukup mengimplementasi timer countdown — bukan fraud proof verification logic.

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
     (compute: setelah challenge period lewat).

> **Catatan Penting (FIX #4):** Pada tahap ini, "finalized" untuk compute receipt berarti challenge timer habis (auto-finalize). Belum ada mekanisme fraud proof yang bisa membatalkan receipt. Fraud proof integration ke reward finalization diimplementasi di Tahap 18.8.

3. **`agent`** — Orchestrasi flow ekonomi end-to-end:
   - Agent mengelola lifecycle: workload dispatch → execution → receipt → claim.
   - Monitoring: track receipt status (pending, challenged, finalized, rejected).
   - Retry logic: jika submission gagal, retry dengan backoff.
   - Metrics/logging: catat semua economic events untuk observability.

4. **`ingress`** — Routing dan endpoint untuk economic transactions:
   - Expose RPC/API endpoint untuk `ClaimReward` submission.
   - Expose endpoint untuk query receipt status dan reward balance.
   - Expose endpoint untuk fraud proof submission (placeholder — accept dan log, tapi belum process/verify).
   - Rate limiting dan basic validation sebelum forward ke chain.

> **Catatan Penting (FIX #4):** Fraud proof endpoint di ingress pada tahap ini adalah **placeholder only**. Endpoint menerima submission dan menyimpan ke log, tapi tidak memicu arbitration atau slashing. Full fraud proof processing diaktifkan di Tahap 18.8.

### Coordinator Committee Formation (FIX #7)

Karena TSS/FROST membutuhkan committee, tahap ini juga mendefinisikan:

**Committee Formation Protocol:**

- Committee terdiri dari `n` coordinator nodes yang menjalankan TSS key shares.
- **Minimum quorum:** `t` dari `n` (threshold), dimana `t = ceil(2n/3) + 1`. Untuk bootstrap, `n=3, t=2` sudah cukup.
- **Formation:** Pada genesis/bootstrap, committee members di-hardcode di genesis config. Pada tahap selanjutnya (post-mainnet), committee membership bisa di-rotate via governance.
- **Rotation:** Belum aktif pada tahap ini. Rotation events di-log (Tahap 15) tapi actual rotation mechanism diimplementasi setelah governance matang (post Tahap 20).
- **Failure handling:**
  - Jika committee member offline saat signing round → timeout → retry tanpa member tersebut.
  - Jika jumlah online members < threshold `t` → signing gagal → receipt pending → retry saat quorum terpenuhi.
  - Persistent failure (member offline > 1 epoch) → log alert, tapi belum auto-rotate pada tahap ini.

**Committee struct:**

```rust
struct CoordinatorCommittee {
    members: Vec<CommitteeMember>,
    threshold: u32,          // minimum signatures needed
    epoch: u64,
    formation_method: FormationMethod, // Genesis | GovernanceVote (future)
}

struct CommitteeMember {
    coordinator_id: PublicKey,
    tss_key_share_index: u32,
    status: MemberStatus, // Active | Offline | Rotating
}

enum FormationMethod {
    Genesis,          // hardcoded at launch
    GovernanceVote,   // future: elected by validators
}
```

**Crates tambahan terlibat:** `coordinator`, `proto`

### Kriteria Selesai 14C.C

- Receipt di-sign dengan real FROST threshold signature (bukan mock).
- Chain verify real threshold signature dan distribute reward.
- Validator menerima 20% share dari finalized receipt.
- Agent bisa orchestrate full flow tanpa manual intervention.
- Ingress endpoints bisa menerima ClaimReward dan return status.
- Ingress fraud proof endpoint menerima submission dan log (placeholder).
- **Coordinator committee terbentuk dari genesis config dengan minimum 2-of-3 threshold (FIX #7).**
- **Committee failure handling tested: member offline → signing tetap sukses jika quorum terpenuhi (FIX #7).**
- Full integration test: node execute → commitment → coordinator TSS sign
  → submit via ingress → chain validate → reward distribute
  (70% node, 20% validator, 10% treasury).
- DA log mencatat semua receipt events.
- Anti-self-dealing, duplicate rejection, dan challenge period (timer-only)
  berfungsi di full integrated flow.

---

## Ringkasan Dependency
```
14C.A (proto, common, chain, coordinator)
  ↓
14C.B (node, runtime_wasm, runtime_vm)
  ↓
14C.C (tss, validator, agent, ingress, + coordinator committee formation)
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
- Coordinator committee rotation events. *(FIX #5: Producer aktif setelah committee rotation diimplementasi post-Tahap 20. Pada tahap ini, definisikan log schema dan hook. Hook akan dipanggil saat rotation mechanism aktif.)*
- DA fallback activation/deactivation events. *(FIX #5: Producer aktif setelah DA fallback diimplementasi di Tahap 15.1. Pada tahap ini, definisikan log schema dan hook.)*
- Compute challenge events. *(FIX #5: Producer aktif setelah fraud proof system diimplementasi di Tahap 18.8. Pada tahap ini, definisikan log schema dan hook. Hook menerima event tapi hanya log — belum trigger action.)*

> **Catatan Implementasi (FIX #5):** Untuk setiap log type yang producer-nya belum exist, implementasi pada tahap ini meliputi:
> 1. Definisikan `LogEventType` enum variant dan schema struct.
> 2. Implementasi log writer yang bisa menerima event dan persist ke WORM + DA.
> 3. Buat trait/interface hook yang bisa dipanggil oleh producer di tahap mendatang.
> 4. Tandai dengan `// Producer: Tahap X` di code.
> 5. Unit test: pastikan hook callable dan log writer berfungsi (dengan synthetic/mock events).

**Selesai jika:** Log--DA sync mirror 100% match. Semua log schema terdefinisi. Hook untuk future producers terimplementasi dan tested dengan mock events.

**Crates yang harus diubah / dilibatkan:** `coordinator`, `storage`, `proto`, `chain`, `node`, `validator`, `agent`, `ingress`, `common`.

> Audit log pada fase ini belum bersifat compliance-grade untuk publik, dan hanya digunakan untuk internal verification dan forensik.

---

## Tahap 16 --- TLS + Node ID + Stake Verification

**Yang baru:**

Coordinator harus menolak node yang: TLS sertifikat invalid, stake kurang dari minimum sesuai role, identitas operator tidak cocok, pernah kena slashing cooldown.

**(FIX #3) Stake requirement per role:**

| Role | Class | Minimum Stake |
|------|-------|---------------|
| StorageCompute | Reguler | 500 $NUSA |
| StorageCompute | DataCenter | 5,000 $NUSA |
| Validator | — | 50,000 $NUSA |
| Coordinator | — | — (no stake requirement) |

Chain Nusantara harus expose API:

```
get_stake(address) -> Amount
get_node_role(address) -> NodeRole
get_node_class(address) -> Option<NodeClass>  // None jika bukan StorageCompute
check_slashing_status(address) -> SlashingStatus
```

**(FIX #3)** Coordinator melakukan validasi gabungan: `get_stake(address)` harus ≥ minimum stake untuk `get_node_role(address)` + `get_node_class(address)`. Contoh:
- Node claim StorageCompute Reguler tapi stake 300 → reject.
- Node claim StorageCompute DataCenter tapi stake 4,000 → reject.
- Node claim Validator tapi stake 10,000 → reject.

Coordinator baru boleh menerima node setelah semua cek lulus.

**(FIX #9) Forward Definition — NodeClass:**

> `NodeClass` enum (`Reguler`, `DataCenter`) harus sudah didefinisikan di crate `common` pada tahap ini untuk digunakan oleh stake verification dan scheduling (Tahap 17). Definisi formal lengkap dengan `NodeIdentity` struct akan di-expand di Tahap 21.1.A, tapi enum dasar harus ada sekarang agar Tahap 16-17 compatible.

```rust
// crates/common/src/node_class.rs — didefinisikan di Tahap 16
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NodeClass {
    Reguler,
    DataCenter,
}
```

**Crates yang harus diubah / dilibatkan:** `coordinator`, `node`, `validator`, `chain`, `agent`, `common`.

> Verifikasi identitas dan stake tidak memberikan kepercayaan operasional terhadap node, melainkan hanya menetapkan kelayakan minimum untuk berpartisipasi. Node tetap diperlakukan sebagai untrusted dalam semua aspek eksekusi dan penyimpanan.

---

## Tahap 17 --- Penjadwalan (Anti-Self-Dealing + Stake Weight)

**Formula baru:**

```
S = w1*CPU + w2*RAM + w3*GPU + w4*(1/latency)
  - w5*IO_pressure + w6*class_weight + w7*stake_weight
```

**Stake Weight (menggunakan `NodeClass` dari Tahap 16):**

- Node reguler (`NodeClass::Reguler`): `log2(stake / 500)`
- Node DC (`NodeClass::DataCenter`): `log2(stake / 5000)`

**Bootstrap system di masa mendatang**
- Node identity (`node_id`, Ed25519 public key) yang sudah diimplementasi di tahap ini juga digunakan sebagai peer ID dalam bootstrap system (Tahap 21). Pastikan `node_id` format compatible dengan peer identification di bootstrap handshake.
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

> **Catatan Integrasi (FIX #4):** Tahap ini mengubah behavior challenge period yang sebelumnya timer-only (sejak 14C.B) menjadi **active fraud proof system**. Setelah tahap ini selesai:
> - Ingress fraud proof endpoint (dari 14C.C) diaktifkan untuk processing — bukan hanya logging.
> - Chain validation ditambah: fraud proof verification sebelum reward finalization.
> - Validator reward finalization untuk compute receipt sekarang bergantung pada "no successful challenge" — bukan hanya timer habis.
> - Tahap 15 log hooks untuk "compute challenge events" sekarang terhubung ke actual producer.

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

### Post-Implementation Integration Checklist

> **(FIX #4)** Setelah tahap ini selesai, lakukan integrasi balik ke komponen yang sebelumnya timer-only:
> - [ ] Ingress: fraud proof endpoint → aktifkan processing (bukan hanya log).
> - [ ] Chain: reward finalization → cek fraud proof status sebelum distribute.
> - [ ] Validator: reward claim → pastikan "no successful challenge" sebelum finalize.
> - [ ] Tahap 15 hooks: connect compute challenge event producer ke log system.

### Kriteria Selesai

- `ExecutionTrace` generation functional.
- Merkleized trace verifiable.
- FraudProof submission and verification.
- Interactive game implementation.
- Slashing integration.
- Redundant execution mode (optional).
- **Ingress fraud proof endpoint activated (bukan placeholder lagi).**
- **Tahap 15 compute challenge log hooks connected.**

**Crates terlibat:** `runtime_wasm`, `runtime_vm`, `chain`, `coordinator`, `node`, `validator`, `proto`, `common`, `ingress`.

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

**(FIX #8)** Semua SDK berada di directory `sdks/` untuk konsistensi. Rust SDK adalah wrapper/re-export dari internal crates.

```
sdks/sdk_rust/       -- Rust SDK (public API, wraps internal crates)
sdks/sdk_python/     -- Python SDK
sdks/sdk_js/         -- JavaScript/TypeScript SDK
sdks/sdk_go/         -- Go SDK
```

> **Catatan (FIX #8):** `sdks/sdk_rust/` bukan crate internal — ia adalah public-facing SDK yang re-exports dan simplifies API dari internal crates. Internal crates (`crates/*`) tetap digunakan dalam DSDN codebase sendiri. SDK Rust ini ditujukan untuk developer eksternal yang membangun di atas DSDN.

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
  -> If challenge -> arbitration (via fraud proof system, Tahap 18.8)

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

## Tahap 20.A --- Mainnet Preparation (With Identity Verification)

**(FIX #1) PENTING: Tahap ini dipecah menjadi dua bagian untuk menghilangkan circular dependency dengan Tahap 21.**

### 20.A-Core — Genesis & Infrastructure Preparation

**Tidak bergantung pada bootstrap system. Bisa dikerjakan sebelum Tahap 21.**

**Tambahan:**

- Node reguler tidak wajib KYC.

Pada genesis: stake requirement embed, multisig validator embed, slashing rules embed.

**Tambahan pada genesis:**

- DA fallback configuration.
- Coordinator committee initial members.
- TSS key ceremony results.
- Fraud proof parameters.

**Kriteria Selesai 20.A-Core:**

- Genesis config lengkap dengan semua parameter di atas.
- TSS key ceremony berhasil dan keys terdistribusi ke committee members.
- Semua parameter embed di genesis block.
- Identity verification flow tested.

### 20.A-Bootstrap — Bootstrap Infrastructure Readiness

**Depends on: Tahap 21.1.C (bootstrap system fully implemented). Dikerjakan SETELAH Tahap 21.**

Checklist bootstrap infrastructure:

- DNS seed domain(s) telah dibeli dan DNS A record aktif.
- Minimal 1 dedicated bootstrap node running 24/7.
- Bootstrap config default sudah terisi dengan DNS seed production.
- `peers.dat` path sudah di-set di production config.
- Full bootstrap test dari fresh node berhasil (semua role: StorageCompute Reguler, StorageCompute DataCenter, Validator, Coordinator).

**Kriteria Selesai 20.A-Bootstrap:**

- DNS seed resolvable dari berbagai lokasi.
- Bootstrap node operational 24/7.
- Fresh node bisa bootstrap dan menjadi operational dalam < 60 detik.

**Crates yang harus diubah / dilibatkan:** `chain`, `validator`, `coordinator`, `node`, `ingress`, `agent`.

> Mainnet pada tahap ini belum dianggap production public network, dan hanya dibuka untuk operator dan pilot terverifikasi. Mainnet pada tahap ini belum boleh dipresentasikan sebagai jaringan trustless, permissionless, atau censorship-resistant.

---

## Tahap 20.A.1 --- Compliance Framework (No Data Access)

Validator hanya boleh: baca metadata, memblokir endpoint/pointer. Validator tidak boleh buka data (encrypted).

**Tambahan blueprint v0.5.2:** Validator tidak bisa delete chunk. Deletion hanya bisa dilakukan oleh user melalui User-Controlled Delete.

**Crates yang harus diubah / dilibatkan:** `validator`, `chain`, `coordinator`, `ingress`, `node`.

> Catatan: Tahap ini berjalan dalam Bootstrap / Transition Governance Mode, tanpa kewenangan governance penuh.

---

## Tahap 21 --- Bootstrap Network System (DNS Seed + Peer Discovery)

**Tujuan:** Mengimplementasikan sistem bootstrap jaringan DSDN berbasis DNS seed dan IP publik, menggunakan **single port untuk semua role**. Setiap node listen di port `45831` apapun role-nya. Setelah handshake, node saling tahu role dan kelas masing-masing, lalu memfilter peer sesuai kebutuhan. Sistem ini mengikuti model Bitcoin: DNS seed → peer exchange → local cache → self-sustaining network.

**(FIX #1) Depends on:** Tahap 20.A-Core (genesis config, TSS ceremony, fraud proof params ready). **Tidak bergantung pada** 20.A-Bootstrap — justru 20.A-Bootstrap bergantung pada tahap ini.

**Prinsip Arsitektur Single-Port:**

- **Satu port untuk semua**: Port `45831` adalah satu-satunya port jaringan DSDN. Semua role dan kelas node listen di port yang sama.
- **Role & kelas diketahui setelah handshake**: DNS seed dan static IP hanya memberikan `IP:45831`. Node baru connect dulu, lalu handshake mengungkapkan role dan kelas dari peer tersebut.
- **Filter setelah handshake**: Node connect ke IP dari DNS → handshake → cek role → jika role tidak dibutuhkan, politely disconnect dan simpan info role-nya untuk referensi node lain via PEX.
- **Semua peer di-cache**: Walaupun role tidak match kebutuhan langsung, peer tetap disimpan di `peers.dat` dengan role dan kelas-nya.

**Catatan Arsitektur: Blockchain Nusantara Embedded**

Sesuai whitepaper DSDN, blockchain Nusantara **bukan komponen terpisah** — ia berjalan embedded di semua node DSDN. Setiap node menjalankan blockchain client sebagai bagian dari sistemnya:

- **Validator**: Menjalankan PoS consensus, memproduksi block, memfinalisasi transaksi.
- **Full Node (StorageCompute)**: Menjalankan blockchain full/light client untuk verifikasi transaksi, validasi billing event, dan membaca state on-chain.
- **Coordinator**: Menjalankan blockchain client untuk stake verification, membaca registry on-chain, dan posting event ke Celestia DA.

Karena blockchain embedded, **tidak ada role "Chain" yang terpisah**. Konsensus PoS dijalankan oleh validator, sementara node lain sync state blockchain secara otomatis.

**Roles (sesuai whitepaper):**

| Role | Kelas | Fungsi | Stake |
|------|-------|--------|-------|
| `StorageCompute` | `Reguler` | Storage kecil, compute ringan, RF=3 chunking | 500 $NUSA |
| `StorageCompute` | `DataCenter` | Storage besar, GPU, SLA tinggi, prioritas scheduler | 5,000 $NUSA |
| `Validator` | — | Governance, compliance, PoS consensus blockchain Nusantara | 50,000 $NUSA |
| `Coordinator` | — | Metadata global, scheduling, job queue, replay Celestia blob | — |

**Catatan Pre-Mainnet Wajib:** Founder harus membeli minimal 1 domain untuk DNS seed sebelum mainnet launch (contoh: `seed1.dsdn.network`). Domain tambahan sangat disarankan untuk redundansi. *(Checklist detail ada di 20.A-Bootstrap)*

---

## 21.1.A --- Bootstrap Config & Seed Registry Foundation

**Tujuan:** Membuat file `bootstrap_system.rs` di crate `common` yang berisi konfigurasi seed DNS, daftar IP publik statis, role & kelas definitions, dan logic registry seed. File ini menjadi sumber kebenaran bootstrap untuk seluruh komponen DSDN.

### Kenapa di crate `common`?

Karena semua komponen DSDN (storage-compute, validator, coordinator) membutuhkan bootstrap. Menaruh di `common` menghindari duplikasi dan menjamin konsistensi konfigurasi di seluruh sistem.

### File Baru: `crates/common/src/bootstrap_system.rs`

Isi modul ini mencakup:

#### 1. Single-Port Architecture, Role & Class Definition

Seluruh jaringan DSDN menggunakan **satu port**: `45831`. Role dan kelas didefinisikan sebagai enum:

**(FIX #2)** `Bootstrap` variant sudah didefinisikan di sini (bukan ditambahkan belakangan di 21.1.C) agar handshake dan PEX di 21.1.B sudah compatible sejak awal.

**(FIX #9)** `NodeRole` dan `NodeClass` di sini meng-extend definisi `NodeClass` yang sudah ada dari Tahap 16 (`crates/common/src/node_class.rs`). `NodeClass` enum tetap satu definisi — tidak duplikasi.

```rust
pub const DSDN_DEFAULT_PORT: u16 = 45831;

/// Role operasional node di jaringan DSDN.
/// Blockchain Nusantara berjalan embedded di semua role — bukan role terpisah.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NodeRole {
    /// Full node: storage + compute.
    /// Kelas (Reguler/DataCenter) menentukan kapasitas dan stake requirement.
    StorageCompute,

    /// Validator: governance, compliance, PoS consensus blockchain Nusantara.
    /// Memproduksi block, memfinalisasi transaksi, menjalankan voting.
    Validator,

    /// Coordinator: metadata, scheduling, job queue, Celestia blob replay.
    /// Stateless scheduler — semua keputusan bisa direkonstruksi dari DA log.
    Coordinator,

    /// Bootstrap: dedicated peer discovery node (non-operational).
    /// Tidak menjalankan storage, compute, consensus, atau scheduling.
    /// Hanya melayani handshake dan PEX — "yellow pages" jaringan.
    /// Tidak memerlukan stake.
    /// (FIX #2: Didefinisikan di 21.1.A agar 21.1.B handshake & PEX sudah compatible)
    Bootstrap,
}

// NodeClass sudah didefinisikan di crates/common/src/node_class.rs sejak Tahap 16.
// Re-export di sini untuk convenience:
pub use crate::node_class::NodeClass;
// NodeClass::Reguler dan NodeClass::DataCenter

/// Informasi lengkap identitas node saat handshake.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub role: NodeRole,
    /// Hanya relevan jika role == StorageCompute.
    /// Validator, Coordinator, dan Bootstrap tidak punya kelas — field ini None.
    pub node_class: Option<NodeClass>,
    pub node_id: Ed25519PublicKey,
    pub network_id: String,        // "mainnet" | "testnet"
    pub protocol_version: u32,
    pub listen_port: u16,          // selalu 45831
    pub capabilities: Vec<String>, // future extension
}
```

**Kenapa role dan kelas dipisah?**

Karena whitepaper DSDN mendefinisikan Full Node Reguler dan Full Node Data Center sebagai **dua kelas dari role yang sama** (storage & compute), bukan dua role berbeda. Validator dan Coordinator tidak punya kelas — mereka berdiri sendiri. Pemisahan ini menjaga konsistensi dengan whitepaper:

- `StorageCompute` + `Reguler` = Full Node Reguler (500 $NUSA)
- `StorageCompute` + `DataCenter` = Full Node Data Center (5,000 $NUSA)
- `Validator` + `None` = Validator (50,000 $NUSA)
- `Coordinator` + `None` = Coordinator
- `Bootstrap` + `None` = Bootstrap node (no stake)

**Handshake validation rules untuk `Bootstrap` (FIX #2):**
- `Bootstrap` role: `node_class` HARUS `None`.
- `Bootstrap` node tidak memerlukan stake verification.
- `Bootstrap` node tidak di-dispatch workload.
- Semua role treat `Bootstrap` peer sebagai PEX-only (connect → PEX → disconnect).

#### 2. Seed DNS Config

Struct konfigurasi yang menyimpan daftar DNS seed. DNS seed tidak mengetahui role — ia hanya return IP address. Role baru diketahui setelah handshake.

Contoh format seed DNS yang akan diisi menjelang mainnet:
```
seed1.dsdn.network  →  resolve ke [IP_A, IP_B, IP_C, ...]
seed2.dsdn.network  →  resolve ke [IP_D, IP_E, ...]
```

Alur dari DNS ke role filtering:
```
1. Validator baru start
2. Resolve seed1.dsdn.network → dapat [IP_A, IP_B, IP_C]
3. Connect ke IP_A:45831 → handshake → role=StorageCompute, class=Reguler
   → Validator butuh StorageCompute? → SKIP → simpan di peers.dat, disconnect
4. Connect ke IP_B:45831 → handshake → role=Validator
   → Validator butuh Validator? → REQUIRED → keep connection
5. Connect ke IP_C:45831 → handshake → role=Coordinator
   → Validator butuh Coordinator? → REQUIRED → keep connection
```

Aturan seed DNS:
- Setiap seed DNS di-resolve ke satu atau lebih IP address (A record / AAAA record).
- Satu seed bisa return banyak IP (round-robin DNS). IP bisa milik node dengan role apapun.
- Seed list bisa ditambah oleh founder, komunitas, atau operator melalui config file.
- Minimal 1 seed wajib ada untuk mainnet, direkomendasikan 3+.
- DNS seed TIDAK role-aware — semua role tercampur di satu DNS record.

#### 3. Static IP Registry

Daftar IP publik statis sebagai alternatif DNS seed. Semua IP menggunakan port `45831`. Role-nya baru diketahui setelah handshake.

Format: `IP:45831` (port selalu 45831, bisa di-omit dan default ke 45831).

Aturan IP statis:
- Bisa ditambah siapa saja melalui config file atau CLI.
- Bisa 0 (kosong) jika hanya mengandalkan DNS seed.
- Tidak ada batas jumlah.
- IP yang invalid atau unreachable akan di-skip otomatis.
- Port default `45831` jika tidak disertakan.

#### 4. Bootstrap Config File (`root_dsdn/dsdn.toml`)

```toml
[bootstrap]
# Node role for this instance
role = "storage-compute"  # storage-compute | validator | coordinator | bootstrap

# Node class (hanya relevan untuk storage-compute)
# Diabaikan jika role bukan storage-compute
node_class = "reguler"  # reguler | datacenter

# Network port (single port for all roles)
port = 45831

# Network identity
network_id = "mainnet"  # mainnet | testnet

# DNS seeds (founder/community maintained)
# Seeds return mixed-role peers — filtering happens after handshake
dns_seeds = [
    # "seed1.dsdn.network",
    # "seed2.dsdn.network",
    # "seed3.dsdn.network",
]

# Static IP peers (community maintained)
# All use port 45831 — role unknown until handshake
static_peers = [
    # "203.0.113.50:45831",
    # "198.51.100.10:45831",
]

# Local peer cache
peers_file = "peers.dat"

# Connection settings
max_outbound_connections = 8
max_inbound_connections = 125
dns_resolve_timeout_secs = 10
peer_connect_timeout_secs = 5
```

#### 5. Role Dependency Matrix

Setiap role memiliki kebutuhan koneksi yang berbeda. Ini menentukan peer mana yang di-keep vs di-disconnect setelah handshake:

**(FIX #2)** Matrix sudah menyertakan `Bootstrap` role sebagai peer type:

```
StorageCompute (Reguler maupun DataCenter) membutuhkan:
  - StorageCompute (REQUIRED)  → data replication antar node, chunk transfer
  - Coordinator (REQUIRED)     → register diri, terima task, report status
  - Validator (OPTIONAL)       → baca keputusan governance jika perlu
                                  (biasanya cukup via blockchain state)
  - Bootstrap (PEX_ONLY)       → PEX lalu disconnect

Validator membutuhkan:
  - Validator (REQUIRED)       → PoS consensus, block production, governance voting
  - Coordinator (REQUIRED)     → koordinasi, status jaringan
  - StorageCompute (OPTIONAL)  → monitoring node health, verifikasi compliance
                                  (bisa juga via on-chain data)
  - Bootstrap (PEX_ONLY)       → PEX lalu disconnect

Coordinator membutuhkan:
  - Coordinator (REQUIRED)     → multi-coordinator sync, committee (TSS/FROST)
  - StorageCompute (REQUIRED)  → task dispatch, node management, health check
  - Validator (REQUIRED)       → stake verification, governance decision reads
  - Bootstrap (PEX_ONLY)       → PEX lalu disconnect

Bootstrap membutuhkan:
  - ALL ROLES (ACCEPT)         → accept semua koneksi, serve PEX, no keep
```

Aturan koneksi:
- `REQUIRED`: Node HARUS punya minimal 1 peer dengan role ini. Jika belum ada, terus cari.
- `OPTIONAL`: Bagus jika ada, tapi tidak blocking. Informasi biasanya bisa didapat via blockchain state.
- `PEX_ONLY`: Connect → request PEX → disconnect. Simpan di peers.dat.
- `SKIP`: Disconnect setelah handshake, tapi tetap simpan di `peers.dat` agar bisa di-share via PEX.

**Catatan tentang blockchain sync:**

Karena blockchain embedded di semua node, setiap node perlu sync blockchain state. Namun blockchain sync BUKAN melalui bootstrap P2P khusus — ia menggunakan mekanisme internal blockchain Nusantara (PoS peer discovery antar validator, block propagation). Yang di-handle bootstrap system ini adalah **discovery antar komponen DSDN** (siapa storage node, siapa coordinator, siapa validator) agar bisa beroperasi sesuai fungsinya masing-masing.

Hubungan blockchain sync dan bootstrap:
```
- Validator menemukan Validator lain via bootstrap → lalu menjalankan PoS consensus di antara mereka.
- StorageCompute menemukan Coordinator via bootstrap → register diri → mulai terima task.
- Coordinator menemukan Validator via bootstrap → baca stake/registry dari blockchain.
- Semua node sync blockchain state dari Validator (block propagation) setelah bootstrap selesai.
```

#### 6. Seed Priority & Fallback Order

Implementasi urutan fallback (sama untuk semua role):

```
1. Coba peers dari peers.dat (local cache, paling cepat)
   → Filter by role yang dibutuhkan (lihat Role Dependency Matrix)
   → Jika ada peer valid dan reachable dengan role yang cocok → gunakan
   → Jika tidak ada yang cocok → coba peer role apapun untuk PEX
   → Jika semua gagal atau peers.dat kosong → lanjut ke 2

2. Coba static IP peers dari config
   → Connect ke IP:45831 → handshake → cek role & kelas
   → Jika role cocok → keep connection, simpan ke peers.dat
   → Jika role tidak cocok → simpan ke peers.dat (dengan role & kelas), disconnect
   → Jika IP unreachable → skip, coba IP berikutnya
   → Jika semua IP gagal → lanjut ke 3

3. Coba DNS seeds dari config
   → Resolve seed1 → dapat IP list → connect satu per satu ke port 45831
   → Handshake → cek role & kelas → keep jika cocok, simpan semua ke peers.dat
   → Jika seed1 gagal → coba seed2 → dan seterusnya
   → Jika semua DNS seed gagal → lanjut ke 4

4. Fallback: Kombinasi retry
   → Retry semua sumber di atas dengan exponential backoff
   → Log warning bahwa tidak ada peer yang bisa dihubungi
   → Node tetap hidup dan retry periodik (setiap 30 detik)
```

**Catatan penting fallback**: Karena DNS seed dan static IP berisi mixed-role peers, mungkin saja node sudah berhasil connect tapi belum ketemu role yang dibutuhkan. Dalam kasus ini, node tetap minta PEX dari peer yang sudah terkoneksi (walaupun beda role) untuk menemukan peer dengan role yang tepat.

### Deliverables 21.1.A

1. File `crates/common/src/bootstrap_system.rs` dengan:
   - `NodeRole` enum (StorageCompute, Validator, Coordinator, **Bootstrap** — FIX #2)
   - Re-export `NodeClass` enum dari `crates/common/src/node_class.rs` (Reguler, DataCenter — FIX #9)
   - `NodeIdentity` struct (role + class + node_id + network_id + ...)
   - `BootstrapConfig` struct (termasuk role, class, single port)
   - `DnsSeed`, `StaticPeer`, `SeedRegistry` structs
   - `RoleDependencyMatrix` — logic siapa butuh siapa (**termasuk Bootstrap role** — FIX #2)
2. Parser untuk bootstrap config (dari section `[bootstrap]` di `dsdn.toml`).
3. DNS resolver wrapper yang async, timeout-aware, dan error-tolerant.
4. Fallback chain logic (peers.dat → static IP → DNS seed → retry) dengan role-aware filtering.
5. Unit test: config parsing, role/class validation, role dependency, DNS resolve mock, fallback ordering, invalid seed handling, **Bootstrap role handshake validation** (FIX #2).

### Crates Terlibat

`common`

### Kriteria Selesai

- `BootstrapConfig` bisa di-load dari file config termasuk `role` dan `node_class` field.
- `NodeRole` enum terdefinisi dengan **4 variant** (StorageCompute, Validator, Coordinator, **Bootstrap** — FIX #2).
- `NodeClass` enum terdefinisi dengan 2 kelas (Reguler, DataCenter), hanya valid untuk StorageCompute.
- **`Bootstrap` role: `node_class` harus `None`, tidak memerlukan stake (FIX #2).**
- `RoleDependencyMatrix` bisa menentukan role mana yang REQUIRED/OPTIONAL/PEX_ONLY/SKIP untuk setiap role **termasuk Bootstrap** (FIX #2).
- Config dengan `role = "validator"` dan `node_class = "datacenter"` → error (validator tidak punya kelas).
- **Config dengan `role = "bootstrap"` dan `node_class = "reguler"` → error (bootstrap tidak punya kelas) (FIX #2).**
- DNS seed list dan static IP list bisa kosong.
- Semua IP menggunakan port 45831 secara default.
- Fallback chain logic ter-test dengan semua kombinasi termasuk role match/mismatch dan class scenarios.

---

## 21.1.B --- Peer Discovery, Handshake with Role+Class Exchange & Local Cache (peers.dat)

**Tujuan:** Mengimplementasikan peer discovery melalui DNS resolve dan IP connect, **handshake yang menyertakan role dan kelas node**, peer exchange protocol, dan persistent local cache `peers.dat` dengan role+class metadata.

**Depends on:** 21.1.A (BootstrapConfig, SeedRegistry, NodeRole **including Bootstrap variant**, NodeClass ready)

### 1. DNS Seed Resolution (Role-Agnostic)

DNS seed resolution tidak berubah — DNS tidak tahu role. Yang berubah adalah post-resolution flow:

```
dns_seed "seed1.dsdn.network"
→ DNS A record query
→ returns: [203.0.113.50, 203.0.113.51, 198.51.100.10]
→ shuffle (randomize order)
→ semua IP port 45831
→ connect satu per satu → handshake → baru tahu role & kelas
→ filter berdasarkan kebutuhan (keep/disconnect)
```

Aturan resolve:
- Timeout per DNS query: configurable (default 10 detik).
- Jika DNS return 0 IP → seed dianggap gagal, lanjut ke seed berikutnya.
- Jika DNS return IP tapi semua unreachable → log warning.
- Support IPv4 (A record) dan IPv6 (AAAA record).
- Randomize hasil resolve.
- **Semua IP yang di-resolve di-connect ke port 45831.**

### 2. Peer Connection & Handshake with Role+Class Exchange

Handshake menyertakan **role dan kelas** dari masing-masing node:

```
1. TCP connect ke IP:45831

2. Handshake (role+class aware):
   Kirim NodeIdentity:
     - protocol_version: u32
     - network_id: String ("mainnet" / "testnet")
     - node_id: Ed25519PublicKey
     - role: NodeRole (StorageCompute / Validator / Coordinator / Bootstrap)
     - node_class: Option<NodeClass> (Some(Reguler) / Some(DataCenter) / None)
     - listen_port: u16 (selalu 45831)
     - capabilities: Vec<String>

   Terima NodeIdentity (format yang sama dari peer)

3. Validasi:
   - network_id HARUS sama
   - protocol_version HARUS compatible
   - node_id HARUS valid Ed25519 public key
   - Jika role == StorageCompute, node_class HARUS Some(_)
   - Jika role == Validator, Coordinator, atau Bootstrap → node_class HARUS None

4. Role filtering (post-handshake):
   - Cek RoleDependencyMatrix: apakah role peer ini REQUIRED/OPTIONAL/PEX_ONLY/SKIP?
   - REQUIRED → keep connection aktif
   - OPTIONAL → keep jika belum cukup peer, disconnect jika sudah cukup
   - PEX_ONLY → request PEX → simpan results → disconnect
   - SKIP → simpan peer info ke peers.dat, lalu disconnect

5. Simpan ke peers.dat:
   - SEMUA peer yang berhasil handshake disimpan (role, class, IP, node_id)
   - Terlepas dari apakah koneksi di-keep atau tidak
```

**Contoh skenario handshake:**

```
Coordinator connect ke berbagai node:

→ Peer A: {role: StorageCompute, class: Reguler}
  Coordinator butuh StorageCompute? → REQUIRED → keep connection → dispatch tasks

→ Peer B: {role: StorageCompute, class: DataCenter}
  Coordinator butuh StorageCompute? → REQUIRED → keep connection
  Catatan: Coordinator bisa bedakan Reguler vs DataCenter untuk scheduling priority

→ Peer C: {role: Validator}
  Coordinator butuh Validator? → REQUIRED → keep → baca stake, governance

→ Peer D: {role: Coordinator}
  Coordinator butuh Coordinator? → REQUIRED → keep → multi-coordinator sync

→ Peer E: {role: Bootstrap}
  Coordinator butuh Bootstrap? → PEX_ONLY → request PEX → disconnect
```

```
StorageCompute (Reguler) connect ke berbagai node:

→ Peer X: {role: Coordinator}
  StorageCompute butuh Coordinator? → REQUIRED → keep → register, terima task

→ Peer Y: {role: StorageCompute, class: DataCenter}
  StorageCompute butuh StorageCompute? → REQUIRED → keep → chunk replication

→ Peer Z: {role: Validator}
  StorageCompute butuh Validator? → OPTIONAL → keep jika belum ada, atau disconnect
  Catatan: biasanya cukup baca governance via blockchain state

→ Peer W: {role: Bootstrap}
  StorageCompute butuh Bootstrap? → PEX_ONLY → PEX → disconnect
```

**Disconnect reason codes:**

```rust
pub enum DisconnectReason {
    RoleNotNeeded,
    PexCompleted,     // (FIX #2: untuk Bootstrap peer setelah PEX selesai)
    TooManyPeers,
    NetworkIdMismatch,
    ProtocolIncompatible,
    InvalidHandshake,    // misal: Validator kirim node_class = Some(DataCenter)
    Timeout,
    Banned,
    Shutdown,
}
```

### 3. Peer Exchange Protocol (PEX) — Role+Class Aware

PEX menyertakan role DAN class information:

```
StorageCompute (Reguler) → Coordinator: "GetPeers" request
  → Optional filter: { roles: [StorageCompute, Coordinator] }

Coordinator → StorageCompute: response:
  [
    { ip: "1.2.3.4", port: 45831, role: StorageCompute, class: Reguler, node_id: "...", last_seen: "..." },
    { ip: "5.6.7.8", port: 45831, role: StorageCompute, class: DataCenter, node_id: "...", last_seen: "..." },
    { ip: "9.10.11.12", port: 45831, role: Coordinator, class: null, node_id: "...", last_seen: "..." },
    { ip: "13.14.15.16", port: 45831, role: Validator, class: null, node_id: "...", last_seen: "..." },
  ]
```

**PEX Cross-Role (tetap powerful di single-port):**

```
StorageCompute baru connect ke Validator (OPTIONAL → SKIP jika sudah cukup):
  → Handshake → role = Validator
  → Sebelum disconnect, kirim GetPeers { roles: [Coordinator, StorageCompute] }
  → Validator response: "Saya kenal Coordinator di IP_X, StorageCompute di IP_Y"
  → Disconnect dari Validator
  → Connect ke IP_X (Coordinator) → handshake → REQUIRED → keep!
```

**PEX via Bootstrap node (FIX #2 — primary use case):**

```
StorageCompute baru → resolve DNS → IP = bootstrap node:
  → Handshake → role = Bootstrap
  → Kirim GetPeers { roles: [Coordinator, StorageCompute] }
  → Bootstrap response: semua known peers dengan role tersebut
  → Disconnect dari Bootstrap (PEX_ONLY)
  → Connect ke peer yang dikembalikan → handshake → keep jika REQUIRED
```

**Kegunaan class info di PEX:**

Coordinator bisa menggunakan class info dari PEX untuk scheduling:
- Butuh node untuk workload berat → prioritaskan connect ke peer `StorageCompute:DataCenter`
- Butuh node untuk replikasi ringan → `StorageCompute:Reguler` cukup

Aturan PEX:
- Peer hanya share peer yang berhasil di-connect dalam 24 jam terakhir.
- Response di-limit (max 1000 peer per response).
- Node tidak boleh share peer yang sudah di-ban.
- PEX request di-rate-limit (max 1 request per peer per 15 menit).
- **PEX response HARUS menyertakan role DAN class per peer.**
- Optional role filter di request.
- Jika tidak ada filter, return semua role.

### 4. peers.dat --- Persistent Peer Cache (Role+Class Enriched)

File `peers.dat` menyimpan role dan class per entry:

```
Per entry:
- IP address (IPv4 atau IPv6)
- Port (selalu 45831)
- Node ID (Ed25519 public key)
- Role (StorageCompute / Validator / Coordinator / Bootstrap)
- Class (Reguler / DataCenter / null)   ← null jika bukan StorageCompute
- Last seen timestamp
- Last successful connect timestamp
- Connection success count
- Connection failure count
- Source (dns_seed / static_config / peer_exchange / inbound)
- Network ID (mainnet / testnet)
```

Aturan peers.dat:
- Binary file (compact). JSON mode untuk debug via flag.
- Max entries: 10,000.
- Entries > 30 hari tanpa successful connect → garbage collected.
- Entries gagal 10x berturut-turut → "suspicious", prioritas rendah.
- Write atomik (temp file → rename).
- Saat startup, peers.dat di-load dan peer diurutkan:
  1. **Role match** (REQUIRED role didahulukan)
  2. **Last successful connect** (terbaru duluan)
  3. **Score** (lihat scoring)

**Role+Class-based startup optimization:**

Saat Coordinator start:
```
1. Load peers.dat
2. Filter: ambil peer dengan role Coordinator, StorageCompute, Validator (semua REQUIRED)
3. Sort by last_successful_connect desc
4. Connect ke top-N peer
5. Untuk StorageCompute: prioritaskan DataCenter class jika butuh capacity info
6. Jika tidak cukup → fallback ke static IP dan DNS seed
```

Saat StorageCompute start:
```
1. Load peers.dat
2. Filter: ambil peer Coordinator (REQUIRED) dan StorageCompute (REQUIRED)
3. Connect → register ke Coordinator → mulai terima task
4. Connect ke StorageCompute lain → chunk replication
5. Validator (OPTIONAL) → connect jika ada, skip jika tidak
```

### 5. Peer Scoring & Selection (Role+Class Weighted)

```
score = base_score
      + (success_count * 2)
      - (failure_count * 3)
      + recency_bonus (< 1 jam: +10, < 24 jam: +5)
      - staleness_penalty (> 7 hari: -5, > 30 hari: -10)
      + role_bonus (REQUIRED: +20, OPTIONAL: +5, PEX_ONLY: +2, SKIP: +0)
      + class_bonus (DataCenter peer jika butuh kapasitas besar: +5)
```

### 6. Peer Rotation & Refresh

- Setiap 30 menit: 1 DNS seed resolve random → connect → handshake → filter by role.
- Setiap 15 menit: PEX request ke 1 random connected peer (bisa request specific roles).
- Setiap 1 jam: coba 2 peer random dari peers.dat yang belum terkoneksi (prioritaskan REQUIRED roles).

### Deliverables 21.1.B

1. DNS seed resolver (async, timeout, multi-seed fallback, IPv4+IPv6) — semua ke port 45831.
2. **Handshake protocol dengan role+class exchange** (NodeIdentity, validation rules, disconnect reason **termasuk PexCompleted**).
3. **Role+class filtering logic post-handshake** (keep/disconnect per RoleDependencyMatrix **termasuk PEX_ONLY untuk Bootstrap**).
4. **PEX dengan role+class metadata** — optional role filter, response termasuk class. **PEX via Bootstrap node tested** (FIX #2).
5. **peers.dat dengan role+class fields** — read/write/GC/role-class-based sorting. **Bootstrap entries stored** (FIX #2).
6. Peer scoring dengan role+class weighting.
7. Peer rotation background task.
8. Unit test: handshake validation (termasuk invalid class untuk Validator **dan Bootstrap**), role filtering, PEX, peers.dat, scoring.
9. Integration test: node StorageCompute + Coordinator + Validator **+ Bootstrap** bootstrap dari 1 DNS seed, handshake, role+class filter, PEX.

### Crates Terlibat

`common`, `node`, `proto` (handshake message dengan role+class field dan PEX message definitions)

### Kriteria Selesai

- Semua koneksi menggunakan single port 45831.
- Handshake menyertakan `role` dan `node_class` — kedua node saling tahu.
- Validator yang kirim `node_class = Some(DataCenter)` → handshake ditolak (invalid).
- **Bootstrap yang kirim `node_class = Some(Reguler)` → handshake ditolak (invalid) (FIX #2).**
- Node bisa filter peer berdasarkan role+class setelah handshake.
- **Node yang connect ke Bootstrap → PEX → disconnect (PEX_ONLY flow) (FIX #2).**
- PEX menyertakan role+class per peer.
- peers.dat menyimpan role+class dan bisa difilter saat startup.
- Cross-role PEX bekerja: connect ke peer beda role → PEX → dapat info peer yang dibutuhkan.
- Fallback chain fully functional dengan role-aware filtering.

---

## 21.1.C --- Full System Integration & Network Resilience

**Tujuan:** Mengintegrasikan bootstrap system ke seluruh komponen DSDN sehingga semua role bisa saling menemukan melalui single-port P2P + role+class handshake, dan memastikan jaringan resilient terhadap berbagai failure scenario.

**Depends on:** 21.1.A (config, role+class definitions **including Bootstrap**), 21.1.B (discovery, handshake, peers.dat)

### 1. Integrasi ke Setiap Role

#### StorageCompute — Reguler (`role = "storage-compute"`, `node_class = "reguler"`)
```
Startup:
1. Load BootstrapConfig: role=StorageCompute, class=Reguler
2. Bootstrap → connect ke IP:45831 → handshake → filter:
   - Peer Coordinator → KEEP → register diri, terima task
   - Peer StorageCompute (Reguler/DataCenter) → KEEP → chunk replication
   - Peer Validator → OPTIONAL → keep jika belum ada, simpan jika skip
   - Peer Bootstrap → PEX_ONLY → PEX → disconnect
3. Setelah punya Coordinator + StorageCompute peer → operational
4. Blockchain sync: connect ke Validator untuk block propagation (via internal blockchain protocol)
```

#### StorageCompute — DataCenter (`role = "storage-compute"`, `node_class = "datacenter"`)
```
Startup: Sama seperti Reguler, tapi:
- Lebih banyak outbound connections (kapasitas lebih besar)
- Menerima lebih banyak inbound dari Coordinator (prioritas scheduler)
- Mengiklankan class=DataCenter saat handshake
```

#### Validator (`role = "validator"`)
```
Startup:
1. Load BootstrapConfig: role=Validator
2. Bootstrap → connect → handshake → filter:
   - Peer Validator → KEEP → PoS consensus, block production, governance voting
   - Peer Coordinator → KEEP → koordinasi, status jaringan
   - Peer StorageCompute → OPTIONAL → monitoring, compliance check
   - Peer Bootstrap → PEX_ONLY → PEX → disconnect
3. Setelah punya Validator peer(s) + Coordinator → operational
4. Mulai participate di PoS consensus → memproduksi/memfinalisasi block
5. Block di-propagate ke semua node (StorageCompute, Coordinator) via blockchain protocol
```

#### Coordinator (`role = "coordinator"`)
```
Startup:
1. Load BootstrapConfig: role=Coordinator
2. Bootstrap → connect → handshake → filter:
   - Peer Coordinator → KEEP → multi-coordinator sync (TSS/FROST)
   - Peer StorageCompute → KEEP → task dispatch, manage nodes
     → Bisa bedakan Reguler vs DataCenter dari handshake class info
   - Peer Validator → KEEP → stake verification, governance reads
   - Peer Bootstrap → PEX_ONLY → PEX → disconnect
3. Setelah punya Coordinator + StorageCompute + Validator → operational
4. Mulai consume Celestia blob → build local state → scheduling
```

### 2. Bootstrap Node (Dedicated)

Founder dan komunitas bisa menjalankan dedicated bootstrap node yang hanya melayani peer discovery:

```bash
dsdn-node --mode bootstrap --listen 0.0.0.0:45831 --network mainnet
```

Bootstrap node behavior:
- Listen di port 45831.
- Handshake mengirim role: `Bootstrap` **(sudah ada di NodeRole enum sejak 21.1.A — FIX #2)**.
- Tidak menjalankan storage, compute, consensus, atau scheduling.
- Hanya melayani handshake dan PEX — menjadi "yellow pages" jaringan.
- Mengumpulkan peer info (role+class) dari semua node yang connect.
- DNS seed biasanya mengarah ke bootstrap node ini.
- Resource requirement sangat rendah (VPS kecil cukup).

```
Alur via bootstrap node:
1. StorageCompute baru → resolve seed1.dsdn.network → IP bootstrap node
2. Connect ke bootstrap_IP:45831 → handshake → role = Bootstrap
3. Minta PEX { roles: [Coordinator, StorageCompute] }
4. Bootstrap response: "Coordinator di IP_X, StorageCompute di IP_Y dan IP_Z"
5. Disconnect dari bootstrap → connect ke IP_X, IP_Y, IP_Z
6. Handshake masing-masing → role match → keep!
```

> **Catatan (FIX #2):** Tidak perlu menambahkan `Bootstrap` ke `NodeRole` enum di tahap ini — sudah ada sejak 21.1.A. Tahap ini hanya mengimplementasi bootstrap node runtime behavior dan CLI.

### 3. Blockchain Sync Integration

Karena blockchain Nusantara embedded di semua node, bootstrap system juga memfasilitasi awal dari blockchain sync:

```
Setelah bootstrap selesai dan node punya peer:
1. StorageCompute:
   - Punya peer Validator (langsung atau via PEX) → sync blockchain blocks
   - Minimal sebagai light client → verifikasi transaksi billing, stake registry
   - Bisa juga full sync untuk audit

2. Validator:
   - Punya peer Validator lain → mulai PoS consensus
   - Minimal 1 validator (whitepaper: "blockchain bisa hidup dengan 1 validator")
   - Target: 100-150 validator untuk full governance

3. Coordinator:
   - Sync blockchain → baca stake registry, node registry
   - Consume Celestia blob → build scheduling state
```

Bootstrap system **mempertemukan** node-node ini, lalu blockchain protocol internal mengambil alih untuk block sync dan consensus. Bootstrap system dan blockchain protocol berjalan di port yang sama (45831) tapi menggunakan message type yang berbeda setelah handshake.

### 4. Network Partition Recovery

```
Deteksi:
- Jumlah connected peer turun di bawah min_peers threshold
- Tidak menerima block baru dalam waktu lama (blockchain stall)
- Jumlah peer dengan REQUIRED role turun ke 0
- Khusus Validator: tidak bisa participate di consensus (tidak cukup quorum)

Recovery:
1. Aggressive DNS seed resolve (semua seed) → connect → handshake → filter role
2. Retry semua peer di peers.dat (terutama REQUIRED roles)
3. Retry semua static IP
4. Jika masih gagal: log critical, retry exponential backoff
```

### 5. Seed Infrastructure Checklist (Pre-Mainnet)

> **(FIX #1)** Checklist ini adalah deliverable dari **Tahap 20.A-Bootstrap** (bukan 21.1.C), tapi dicantumkan di sini sebagai referensi karena 20.A-Bootstrap bergantung pada 21.1.C.

```
[ ] Beli minimal 1 domain untuk DNS seed (contoh: seed1.dsdn.network)
[ ] Setup DNS A record mengarah ke bootstrap node IP (port 45831)
[ ] Bootstrap node running 24/7
[ ] Test DNS resolve dari berbagai lokasi geografis
[ ] Test handshake: connect → role=Bootstrap → PEX → dapat peer dengan role berbeda
[ ] (Disarankan) 2 domain tambahan untuk redundansi
[ ] (Disarankan) Bootstrap node di 2-3 lokasi geo-distributed
[ ] (Disarankan) Komunitas/operator menjalankan bootstrap node tambahan
[ ] (Disarankan) 3-5 static IP dari operator terpercaya di default config
[ ] Test full bootstrap per role:
    [ ] Fresh StorageCompute (Reguler) → DNS → find Coordinator+StorageCompute → register → operational
    [ ] Fresh StorageCompute (DataCenter) → DNS → find Coordinator+StorageCompute → register → operational
    [ ] Fresh Validator → DNS → find Validator+Coordinator → PoS consensus → operational
    [ ] Fresh Coordinator → DNS → find Coordinator+StorageCompute+Validator → scheduling → operational
[ ] Test blockchain sync: StorageCompute sync blocks from Validator after bootstrap
[ ] Test fallback: matikan seed1 → failover ke seed2
[ ] Test peers.dat: restart → connect tanpa DNS menggunakan cached role+class info
[ ] Document seed maintenance procedure
```

### 6. Anti-Abuse & Security

- **DNS Poisoning:** Trust dari handshake (network_id, node_id verification), bukan DNS. Role claim diverifikasi via behavior.
- **Role Spoofing:** Mitigasi:
  - StorageCompute yang claim DataCenter tapi kapasitas kecil → Coordinator deteksi saat task dispatch → downgrade class atau ban.
  - Validator yang claim tapi tidak punya 50,000 $NUSA stake → cek on-chain → reject.
  - Coordinator yang claim tapi tidak bisa produce valid scheduling → peer deteksi → disconnect.
  - **Stake-based verification**: Setelah bootstrap, node bisa verify stake peer via blockchain state. Validator tanpa stake = fake.
- **Eclipse Attack:** Connect ke peer dari berbagai sumber. Enforce diversity.
- **Sybil via PEX:** Rate limit PEX. Score berdasarkan behavior.
- **Spam Connection:** Rate limit inbound per IP.
- **peers.dat Poisoning:** Score berdasarkan actual work (block exchange, chunk transfer), bukan hanya handshake.

### 7. Agent CLI Support

```bash
# Lihat semua connected peers (role + class)
dsdn-agent peers list
# Output:
# IP              PORT   ROLE           CLASS       NODE_ID     CONNECTED  SCORE
# 203.0.113.50    45831  StorageCompute Reguler     abc123...   yes        85
# 198.51.100.10   45831  StorageCompute DataCenter  def456...   yes        92
# 192.0.2.100     45831  Validator      -           ghi789...   yes        78
# 10.0.0.5        45831  Coordinator    -           jkl012...   yes        88

# Filter by role
dsdn-agent peers list --role storage-compute
dsdn-agent peers list --role validator
dsdn-agent peers list --role coordinator
dsdn-agent peers list --role bootstrap

# Filter by role + class
dsdn-agent peers list --role storage-compute --class datacenter
dsdn-agent peers list --role storage-compute --class reguler

# Tambah static peer (port default 45831)
dsdn-agent peers add 203.0.113.50
dsdn-agent peers add 203.0.113.50:45831

# Tambah DNS seed
dsdn-agent peers add-seed seed4.dsdn.network

# Stats (breakdown by role + class)
dsdn-agent peers stats
# Output:
# Total peers in cache: 847
# By role:
#   StorageCompute: 590 (Reguler=412, DataCenter=178)
#   Validator: 142
#   Coordinator: 45
#   Bootstrap: 12
# Connected: 18
#   StorageCompute: 8 (Reguler=5, DataCenter=3)
#   Validator: 5
#   Coordinator: 3
#   Bootstrap: 2
# Last DNS resolve: 12 min ago
# Last PEX: 8 min ago
# Blockchain sync: block #1,234,567 (Validator peer: 5 connected)

# Force re-bootstrap
dsdn-agent peers reset

# Role dependency info
dsdn-agent peers roles
# Output (jika node ini StorageCompute Reguler):
# My role: StorageCompute (Reguler)
# Required peers: StorageCompute, Coordinator
# Optional peers: Validator
# PEX-only peers: Bootstrap
```

### 8. Monitoring & Observability

```
# DNS & Connection
bootstrap_dns_resolve_total
bootstrap_dns_resolve_success
bootstrap_dns_resolve_latency_ms
bootstrap_peer_connect_total              — semua ke port 45831
bootstrap_peer_connect_success

# Handshake & Role Discovery
bootstrap_handshake_total
bootstrap_handshake_success
bootstrap_handshake_failure{reason="..."}
bootstrap_handshake_role_discovered{role="storage_compute|validator|coordinator|bootstrap"}
bootstrap_handshake_class_discovered{class="reguler|datacenter|none"}
bootstrap_peer_disconnect{reason="role_not_needed|pex_completed|too_many_peers|invalid_handshake|..."}

# Peer State
bootstrap_peers_dat_size
bootstrap_peers_dat_by_role{role="..."}
bootstrap_peers_dat_by_class{class="..."}    — breakdown StorageCompute by Reguler/DataCenter
bootstrap_active_peers
bootstrap_active_peers_by_role{role="..."}
bootstrap_active_peers_by_class{class="..."}

# PEX
bootstrap_pex_requests_total
bootstrap_pex_role_filter_used
bootstrap_pex_via_bootstrap_node           — PEX specifically through Bootstrap role peers

# Fallback
bootstrap_fallback_triggered{from="peers_dat|static_ip|dns_seed"}

# Role Health
bootstrap_required_role_missing{role="..."}   — alert: REQUIRED role tapi 0 peer
bootstrap_time_to_first_required_peer_ms

# Blockchain Sync (post-bootstrap)
bootstrap_blockchain_sync_started            — blockchain sync dimulai setelah bootstrap
bootstrap_blockchain_peer_count              — jumlah peer yang provide block sync
```

### Integration Test Scenarios

1. **Fresh StorageCompute (Reguler), DNS only:** Start → DNS → handshake → beberapa bukan StorageCompute/Coordinator → PEX → find Coordinator + StorageCompute → register → operational.
2. **Fresh StorageCompute (DataCenter), static IP only:** DNS kosong → static IP → handshake → handshake menyertakan class=DataCenter → Coordinator prioritaskan → operational.
3. **Fresh Validator:** Start → DNS → find Validator peers → PoS consensus mulai → find Coordinator → operational.
4. **Fresh Coordinator:** Start → DNS → find Coordinator + StorageCompute + Validator → scheduling → operational.
5. **Warm restart (role+class cached):** peers.dat punya role+class info → langsung connect ke peer yang tepat → operational < 5 detik.
6. **All DNS seeds down:** Fallback ke static IP → berhasil.
7. **Semua sumber down:** Retry dengan backoff → saat kembali → connect.
8. **Cross-role PEX discovery:** StorageCompute connect ke Validator → PEX → dapat Coordinator info → connect → operational.
9. **Bootstrap node as hub:** Node per role + 1 bootstrap → semua via bootstrap → PEX → semua menemukan peer yang dibutuhkan.
10. **Network partition recovery:** 2 group terisolasi → DNS seed → reconnect.
11. **PEX propagation:** 10 node mixed roles → hanya node 1 kenal DNS → PEX rounds → semua menemukan peers.
12. **Role spoofing - Validator tanpa stake:** Node claim Validator → peer cek on-chain → no stake → disconnect + ban.
13. **Class spoofing - claim DataCenter tapi Reguler:** Coordinator dispatch heavy task → node gagal → Coordinator downgrade class di local registry.
14. **Multi-role startup simultaneously:** StorageCompute(R) + StorageCompute(DC) + Validator + Coordinator start bersamaan → bootstrap → semua saling temukan → operational.
15. **peers.dat corruption:** Corrupt/deleted → fallback DNS → rebuild dengan role+class info.
16. **Single port verification:** Semua koneksi hanya port 45831.
17. **Blockchain sync post-bootstrap:** StorageCompute berhasil bootstrap → connect ke Validator → sync block → verify transaksi.
18. **Minimal operational (whitepaper):** 1 Validator + 3 StorageCompute di 3 zona + 1 Coordinator → semua bootstrap → DSDN operational.

### Deliverables 21.1.C

1. Integrasi `BootstrapConfig` ke semua role: StorageCompute (Reguler+DataCenter), Validator, Coordinator.
2. Per-role startup flow dengan role+class-based peer filtering.
3. Blockchain sync initiation setelah bootstrap (Validator discovery → block propagation).
4. Dedicated bootstrap node mode (`--mode bootstrap`).
5. Network partition detection dan recovery (role-aware).
6. Anti-abuse: rate limiting, eclipse attack mitigation, role+class spoofing detection, stake-based verification.
7. Agent CLI dengan role+class filtering.
8. Monitoring metrics dengan role+class breakdown.
9. Seed infrastructure checklist *(ownership: 20.A-Bootstrap, referenced here)*.
10. Full integration test suite (18 scenarios).
11. End-to-end test: semua role+class bootstrap dari nol via single port, saling menemukan, blockchain sync, operational.

### Crates Terlibat

`common`, `node`, `coordinator`, `validator`, `agent`, `proto`

### Kriteria Selesai

- **Single port confirmed**: Semua komponen hanya port 45831.
- **Role+class discovery works**: Handshake menyertakan role DAN class. Filtering sesuai RoleDependencyMatrix.
- **Tidak ada role "Chain" terpisah**: Blockchain Nusantara berjalan embedded di semua node. Validator menjalankan PoS consensus, node lain sync block.
- **StorageCompute class distinction**: Reguler dan DataCenter di-advertise saat handshake dan di-cache di peers.dat. Coordinator bisa bedakan untuk scheduling.
- **Bootstrap role functional (FIX #2)**: Bootstrap node bisa serve PEX, semua role bisa discover peer via Bootstrap node.
- **Cross-role PEX**: Berfungsi termasuk class info.
- **Fallback chain bekerja** di semua kombinasi.
- **peers.dat role+class aware**: Restart langsung connect ke peer tepat (< 5 detik).
- **Blockchain sync setelah bootstrap**: StorageCompute bisa sync block dari Validator setelah peer discovery selesai.
- **Stake-based role verification**: Validator tanpa stake on-chain → rejected.
- **Anti-abuse active** dan tested.
- **Semua 18 integration test pass.**
- **Monitoring metrics visible** termasuk role+class breakdown.
- **Minimal operational test**: Sesuai whitepaper — 1 Validator + 3 StorageCompute + 1 Coordinator → DSDN berjalan.

---

## Ringkasan Perubahan dari Versi Sebelumnya

| Aspek | Revisi v1 (salah) | Revisi v2 (sesuai whitepaper) |
|-------|-------------------|-------------------------------|
| Roles | Chain, Validator, Coordinator, StorageCompute | **StorageCompute, Validator, Coordinator** (3 role operasional + Bootstrap khusus) |
| "Chain" role | Ada sebagai role terpisah | **Dihapus** — blockchain embedded di semua node |
| Blockchain | Dijalankan oleh "Chain node" | **Validator jalankan PoS consensus, node lain sync** |
| Node class | Tidak ada | **Reguler vs DataCenter** (sub-class StorageCompute) |
| Handshake | Kirim role saja | **Kirim role + node_class** |
| PEX | Role info saja | **Role + class info** |
| peers.dat | Role saja | **Role + class** |
| Stake verification | Tidak ada | **Post-bootstrap: cek on-chain stake** (500/5000/50000 $NUSA) |
| Scheduling awareness | Tidak ada class info | **Coordinator bedakan Reguler vs DataCenter** |
| Integration test | 14 scenarios | **18 scenarios** (tambah blockchain sync, class spoofing, minimal operational) |

| Role (Whitepaper) | Handshake Identity | Stake |
|---|---|---|
| Full Node Reguler | `{role: StorageCompute, class: Reguler}` | 500 $NUSA |
| Full Node Data Center | `{role: StorageCompute, class: DataCenter}` | 5,000 $NUSA |
| Validator | `{role: Validator, class: null}` | 50,000 $NUSA |
| Coordinator | `{role: Coordinator, class: null}` | — |
| Bootstrap (khusus) | `{role: Bootstrap, class: null}` | — |

---

## Ringkasan Dependency (Tahap 21 — FIXED)

**(FIX #1)** Dependency chain yang benar, tanpa circular reference:

```
20.A-Core (Genesis config, TSS ceremony, fraud proof params)
  ↓
21.1.A (Config & Seed Registry — includes Bootstrap role)
  ↓
21.1.B (Discovery, PEX, peers.dat — handles Bootstrap peers)
  ↓
21.1.C (Full System Integration & Resilience)
  ↓
20.A-Bootstrap (DNS seed purchase, bootstrap node deployment, full bootstrap test)
  ↓
Tahap 22 (Mainnet Launch) — semua komponen DSDN fully P2P
```

**20.A-Core** → Genesis preparation. Tidak butuh bootstrap. Bisa paralel dengan development lain.

**21.1.A** → Data layer. Config, struct, DNS resolver, fallback logic. Depends on 20.A-Core untuk genesis params.

**21.1.B** → Network layer. Discovery, handshake, PEX, peers.dat. Depends on 21.1.A.

**21.1.C** → Integration layer. Menyambungkan ke seluruh komponen DSDN + security + monitoring. Depends on 21.1.A + 21.1.B. Tahap paling berat dan paling critical karena melibatkan seluruh crates.

**20.A-Bootstrap** → Infrastructure deployment. Beli domain, deploy bootstrap nodes, test. Depends on 21.1.C.

**Estimasi effort:** 21.1.A (20%), 21.1.B (35%), 21.1.C (45%).

**Crates total yang terlibat:** `common`, `chain`, `node`, `coordinator`, `validator`, `ingress`, `agent`, `proto`.

---

## Tahap 22 --- Mainnet Launch (Limited / Pilot Mainnet)

**Depends on:** 20.A-Bootstrap (bootstrap infrastructure verified and operational).

**Launch Dashboard untuk:**

- Node stake status.
- DA sync status (Celestia + fallback — Tahap 15.1).
- Coordinator committee status.
- Reward distribution.
- Fraud proof challenges active.
- Governance proposal status.

**Pilot Mainnet Characteristics:**

- Limited to verified operators.
- Fraud proof challenge period: conservative (4 hours).
- DA fallback: tested but not publicly advertised.
- Fee: fixed rate, belum adaptive (adaptive fee dan oracle diaktifkan di Tahap 24).
- Subsidy: belum aktif (diaktifkan di Tahap 24.1).

**Crates yang harus diubah / dilibatkan:** `chain`, `coordinator`, `node`, `validator`, `ingress`, `agent`.

> Tidak diperbolehkan klaim "desentralisasi penuh", "trustless", atau "production-ready" dalam komunikasi eksternal.

---

## Appendix: Changelog Fixes Applied

| Fix # | Severity | Issue | Resolution |
|-------|----------|-------|------------|
| 1 | CRITICAL | Circular dependency 20.A ↔ 21 | Split 20.A into 20.A-Core (before 21) and 20.A-Bootstrap (after 21.1.C). Updated dependency chain. |
| 2 | HIGH | Bootstrap variant missing in 21.1.A NodeRole enum | Added `Bootstrap` to NodeRole enum in 21.1.A. Updated RoleDependencyMatrix with PEX_ONLY. Updated handshake validation, PEX, peers.dat throughout 21.1.A/B/C. |
| 3 | HIGH | Tahap 16 stake check missing Validator 50,000 | Added complete stake table (500/5000/50000) and combined role+stake validation to Tahap 16. |
| 4 | MEDIUM | Challenge period ambiguous before fraud proof exists | Added explicit notes in 14C.B, 14C.C that challenge period is timer-only. Added integration checklist in 18.8 for activating real fraud proof. |
| 5 | MEDIUM | Tahap 15 references events from future stages | Added per-log-type annotations marking which producer is from which tahap. Defined hook-based approach with mock event testing. |
| 6 | MEDIUM | DA fallback has no dedicated implementation stage | Created new Tahap 15.1 with DA health monitor, fallback buffer, reconciliation, and activation events. |
| 7 | MEDIUM | Coordinator committee formation undefined | Added committee formation section to 14C.C with protocol, quorum, failure handling, and structs. |
| 8 | LOW | SDK directory structure inconsistent | Moved Rust SDK to `sdks/sdk_rust/` with note that it's a public wrapper over internal crates. |
| 9 | LOW | NodeClass used in Tahap 16-17 before formal definition in 21 | Added forward definition of NodeClass enum in Tahap 16 (`common/src/node_class.rs`). 21.1.A re-exports from this. |

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
- Bootstrap performance: waktu dari fresh node start hingga pertama kali terhubung ke jaringan (target: < 30 detik dengan DNS seed available).
- PEX propagation time: waktu hingga seluruh jaringan test (10 node) saling mengenal (target: < 10 menit).
- peers.dat warm start time: waktu connect dari cache (target: < 5 detik).

**Benchmark targets:**

- DA failover: < 5 minutes.
- TSS signing: < 500ms.
- Trace generation: < 10% overhead.

**Crates yang harus diubah / dilibatkan:** `coordinator`, `storage`, `node`, `chain`, `agent`, `e2e_tests` (file in `crates/chain`).

> Benchmark difokuskan pada validasi determinisme, konsistensi, dan overhead trust model, bukan pada klaim performa komersial.
---

## Tahap 28 NOTE:DI BAGIAN INI DIHAPUS DAN DI PINDAH DI ANTARA 20 dan 21

---

## Tahap 29 --- Geographic Routing (Zone + Class + Stake Aware)

Node dipilih berdasarkan: latensi terdekat, zona berbeda, stake weight, node class, anti-self-dealing.

Ingress harus baca: `node_registry_state` hasil rekonstruksi dari DA.

**Crates yang harus diubah / dilibatkan:** `coordinator`, `ingress`, `node`, `storage`, `chain`.

> Catatan: Tahap ini berjalan dalam Bootstrap / Transition Governance Mode, tanpa kewenangan governance penuh. Keputusan routing harus deterministik berdasarkan state hasil replay DA, dan tidak boleh bergantung pada keputusan imperatif coordinator.

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