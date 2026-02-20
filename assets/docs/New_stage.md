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