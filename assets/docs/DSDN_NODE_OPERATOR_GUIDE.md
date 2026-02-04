# DSDN Node Operator Guide

> **Panduan Lengkap Menjalankan Node di Jaringan DSDN**
> 
> Versi: 1.0.0  
> Tanggal: Januari 2026

---

## Daftar Isi

1. [Pendahuluan](#1-pendahuluan)
2. [Arsitektur DSDN](#2-arsitektur-dsdn)
3. [Persyaratan Hardware](#3-persyaratan-hardware)
4. [Persyaratan Staking](#4-persyaratan-staking)
5. [Setup Celestia Light Node](#5-setup-celestia-light-node)
6. [Konfigurasi DSDN Node](#6-konfigurasi-dsdn-node)
7. [Menjalankan Node](#7-menjalankan-node)
8. [Verifikasi & Monitoring](#8-verifikasi--monitoring)
9. [Troubleshooting](#9-troubleshooting)
10. [FAQ](#10-faq)

---

## 1. Pendahuluan

### Apa itu DSDN?

DSDN (Decentralized Storage Data Network) adalah jaringan data dan komputasi semi-desentralisasi yang menggabungkan:

- **Replikasi data lintas zona** dengan target RF=3 (3 replika di 3 zona berbeda)
- **Eksekusi program terisolasi** (WASM/microVM)
- **Lapisan validator** untuk kepatuhan hukum

DSDN dirancang sebagai sistem **verifiable-by-design**, di mana tidak ada satu pun entitas—termasuk coordinator, validator, maupun foundation—yang memegang kontrol otoritatif atas data, eksekusi, maupun state jaringan.

### Mengapa Menjalankan Node?

Dengan menjalankan node DSDN, Anda:

1. **Mendapatkan reward** dalam token $NUSA dari aktivitas pengguna
2. **Berkontribusi** pada infrastruktur terdesentralisasi Indonesia
3. **Menjadi bagian** dari ekosistem Web3 yang berkembang

### Distribusi Fee

Setiap aktivitas pengguna (upload, download, storage, compute) menghasilkan fee yang dibagi:

| Penerima | Persentase | Keterangan |
|----------|------------|------------|
| Node Operator | 70% | Storage & compute provider |
| Validator | 20% | Staking reward |
| Treasury | 10% | Development & burn |

> ⚠️ **Anti-Self-Dealing**: Node tidak menerima reward dari workload yang di-submit oleh wallet address miliknya sendiri.

---

## 2. Arsitektur DSDN

### Komponen Utama

```
┌─────────────────────────────────────────────────────────────────┐
│                     CELESTIA MAINNET                             │
│              (Data Availability & Ordering Layer)                │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ Blob stream
                              │
┌─────────────────────────────────────────────────────────────────┐
│                    CELESTIA LIGHT NODE                           │
│                (Setiap operator WAJIB menjalankan)               │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ RPC (localhost:26658)
                              │
        ┌─────────────────────┴─────────────────────┐
        │                                           │
        ▼                                           ▼
┌───────────────┐                          ┌───────────────┐
│  COORDINATOR  │                          │   DSDN NODE   │
│  (Scheduler)  │                          │   (Storage)   │
└───────────────┘                          └───────────────┘
```

### Three Planes of DSDN

| Plane | Fungsi | Operator |
|-------|--------|----------|
| **Control Plane** | Metadata, scheduling, billing | Coordinator |
| **Data & Compute Plane** | Storage chunks, execute programs | Full Nodes |
| **Governance & Compliance** | Moderasi, voting | Validators |

### Bagaimana Node Bekerja

1. **Coordinator** mem-publish events ke Celestia DA
2. **Node** mengkonsumsi events dari Celestia
3. **Node** membangun state lokal secara deterministik
4. **Node** menyimpan chunks dan melayani requests

> 💡 **Penting**: Node TIDAK menerima instruksi langsung dari Coordinator via RPC. Semua commands datang via DA layer untuk menjamin verifiability.

---

## 3. Persyaratan Hardware

DSDN mendukung dua kelas node:

### 3.1 Full Node Reguler (Partisipasi Publik)

Cocok untuk: Rumah, kantor kecil, atau server low-cost

| Komponen | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 4 vCPU | 8 vCPU |
| RAM | 8 GB | 32 GB |
| Storage (NVMe) | 512 GB | 2 TB |
| Storage (HDD) | - | 2-4 TB (warm tier) |
| Network | 300 Mbps | 1 Gbps |
| GPU | Opsional | Opsional |
| UPS | Opsional | 5-10 menit |

**Estimasi Biaya Hardware**: Rp 5-15 juta (one-time)

### 3.2 Full Node Data Center (Kapasitas Tinggi)

Cocok untuk: Data center, enterprise, heavy workloads

| Komponen | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 32 vCPU | 64 vCPU |
| RAM | 128 GB | 256 GB |
| Storage (NVMe) | 4 TB | 8 TB |
| Storage (HDD) | 8 TB | 16 TB |
| Network | 10 Gbps | 25 Gbps (dual uplink) |
| GPU | 24 GB VRAM | 48 GB VRAM |
| UPS | 30 menit | 30 menit + genset |

**Estimasi Biaya Hardware**: Rp 100-500 juta (one-time)

### 3.3 Persyaratan Software

| Software | Version | Keterangan |
|----------|---------|------------|
| OS | Ubuntu 22.04+ / Windows 10+ | Linux recommended |
| Rust | 1.75+ | Untuk build dari source |
| Celestia | celestia-node v0.16+ | Light node |

---

## 4. Persyaratan Staking

Untuk mendaftar sebagai node operator, Anda WAJIB melakukan staking token $NUSA:

| Kelas Node | Minimum Stake | Fungsi |
|------------|---------------|--------|
| Full Node Reguler | 500 $NUSA | Sybil-resistance |
| Full Node Data Center | 5,000 $NUSA | Sybil-resistance + SLA guarantee |
| Validator | 50,000 $NUSA | Governance participation |

### Slashing Rules

Stake dapat di-slash jika node berperilaku buruk:

| Pelanggaran | Slash Amount | Cooldown |
|-------------|--------------|----------|
| Liveness failure (>12 jam offline) | 0.5% | - |
| Data corruption (2x berturut) | 5% | 14 hari |
| Repeated malicious behavior | Force unbond | 30 hari banned |

---

## 5. Setup Celestia Light Node

Setiap node operator **WAJIB** menjalankan Celestia light node sendiri. Light node ini yang akan sync dengan Celestia mainnet dan menyediakan data availability untuk DSDN node Anda.

### 5.1 Install Celestia Node

**Linux (Ubuntu/Debian):**

```bash
# Install dependencies
sudo apt update && sudo apt install -y curl tar wget

# Download Celestia node binary
cd /tmp
curl -sLO https://github.com/celestiaorg/celestia-node/releases/download/v0.16.0/celestia-node_Linux_x86_64.tar.gz
tar -xzf celestia-node_Linux_x86_64.tar.gz
sudo mv celestia /usr/local/bin/

# Verify installation
celestia version
```

**Windows:**

Download dari [GitHub Releases](https://github.com/celestiaorg/celestia-node/releases), extract, dan jalankan dari folder tersebut.

### 5.2 Initialize Light Node

```bash
# Initialize untuk Celestia Mainnet
celestia light init --p2p.network celestia
```

### 5.3 Start Light Node

```bash
# Start light node (akan sync dengan mainnet)
celestia light start \
  --core.ip consensus.celestia.org \
  --p2p.network celestia
```

> ⏳ **Sync Time**: Light node akan sync dalam beberapa menit. Full sync tidak diperlukan untuk operasi.

### 5.4 Generate Auth Token

Setelah light node berjalan, generate auth token untuk DSDN:

```bash
# Generate admin auth token
celestia light auth admin --p2p.network celestia
```

**Output contoh:**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBbGxvdyI6WyJwdWJsaWMiLCJyZWFkIiwid3JpdGUiLCJhZG1pbiJdfQ.xxx...
```

> 🔐 **SIMPAN TOKEN INI!** Token ini akan digunakan di konfigurasi DSDN node.

### 5.5 Verify Light Node

```bash
# Check if light node is running
curl -s http://localhost:26658/head | jq .

# Expected: JSON response dengan header info
```

---

## 6. Konfigurasi DSDN Node

### 6.1 Download DSDN Binary

```bash
# Clone repository
git clone https://github.com/novenrizkia856-ui/dsdn
cd dsdn

# Build from source
cargo rustsp build --release

# Binary akan ada di ./target/release/
```

Atau download pre-built binary dari [DSDN Releases](https://github.com/dsdn-network/dsdn/releases).

### 6.2 Buat File Konfigurasi

Buat file `.env.mainnet` di direktori DSDN:

```ini
# ══════════════════════════════════════════════════════════════
# DSDN Node Configuration - Mainnet
# ══════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────
# DATA AVAILABILITY (CELESTIA) CONFIGURATION
# ─────────────────────────────────────────────────────────────

# Celestia Light Node RPC URL
# Ini adalah light node yang ANDA jalankan sendiri
DA_RPC_URL=http://localhost:26658

# DSDN Namespace di Celestia (JANGAN DIUBAH)
# Namespace ini adalah identifier DSDN di Celestia mainnet
DA_NAMESPACE=000000000000000000000000000000000000000064736e6e0000000000

# Auth token dari Celestia light node ANDA
# Dapatkan dengan: celestia light auth admin --p2p.network celestia
DA_AUTH_TOKEN=<PASTE_YOUR_AUTH_TOKEN_HERE>

# Network identifier
DA_NETWORK=mainnet

# ─────────────────────────────────────────────────────────────
# DA CONNECTION SETTINGS
# ─────────────────────────────────────────────────────────────

# Timeout untuk operasi DA (milliseconds)
DA_TIMEOUT_MS=30000

# Retry configuration
DA_RETRY_COUNT=3
DA_RETRY_DELAY_MS=1000

# Connection pooling
DA_ENABLE_POOLING=true
DA_MAX_CONNECTIONS=10
DA_IDLE_TIMEOUT_MS=60000

# ─────────────────────────────────────────────────────────────
# NODE CONFIGURATION
# ─────────────────────────────────────────────────────────────

# Unique identifier untuk node Anda
# Bisa menggunakan hostname, atau string unik apapun
NODE_ID=my-dsdn-node-01

# Path untuk menyimpan data chunks
# Pastikan path ini memiliki cukup space sesuai kelas node Anda
NODE_STORAGE_PATH=./data/node

# HTTP port untuk health check dan metrics
NODE_HTTP_PORT=8081

# ─────────────────────────────────────────────────────────────
# WALLET CONFIGURATION (untuk menerima reward)
# ─────────────────────────────────────────────────────────────

# Wallet address untuk menerima reward
# WALLET_ADDRESS=nusa1xxx...

# ─────────────────────────────────────────────────────────────
# OPTIONAL: COORDINATOR CONNECTION
# ─────────────────────────────────────────────────────────────

# COORDINATOR_HOST=coordinator.dsdn.network
# COORDINATOR_PORT=8080
```

### 6.3 Penjelasan Konfigurasi

| Variable | Required | Keterangan |
|----------|----------|------------|
| `DA_RPC_URL` | ✅ | URL ke Celestia light node Anda |
| `DA_NAMESPACE` | ✅ | Namespace DSDN (sama untuk semua node) |
| `DA_AUTH_TOKEN` | ✅ | Token dari light node Anda |
| `DA_NETWORK` | ✅ | Harus `mainnet` untuk production |
| `NODE_ID` | ✅ | Identifier unik untuk node Anda |
| `NODE_STORAGE_PATH` | ✅ | Lokasi penyimpanan data |
| `NODE_HTTP_PORT` | ✅ | Port untuk health endpoint |

### 6.4 Namespace Explanation

```
DA_NAMESPACE=000000000000000000000000000000000000000064736e6e0000000000
              └──────────────────────────────────────┘└──────────────┘
                        Version 0 padding              "dsdn" in hex
```

Namespace ini adalah identifier DSDN di Celestia. **Semua node HARUS menggunakan namespace yang sama** agar dapat membaca events yang sama dari DA layer.

---

## 7. Menjalankan Node

### 7.1 Linux

**Terminal 1: Celestia Light Node**
```bash
# Jalankan light node (biarkan running)
celestia light start \
  --core.ip consensus.celestia.org \
  --p2p.network celestia
```

**Terminal 2: DSDN Node**
```bash
# Load environment variables
set -a
source .env.mainnet
set +a

# Set node-specific variables
export NODE_ID="my-node-01"
export NODE_STORAGE_PATH="./data/node1"
export NODE_HTTP_PORT="8081"

# Jalankan DSDN node
./target/release/dsdn-node env
```

### 7.2 Windows (PowerShell)

**Terminal 1: Celestia Light Node**
```powershell
# Jalankan light node
celestia light start --core.ip consensus.celestia.org --p2p.network celestia
```

**Terminal 2: DSDN Node**
```powershell
# Load environment variables dari .env.mainnet
Get-Content .env.mainnet | ForEach-Object {
    if ($_ -match '^([^#][^=]+)=(.*)$') {
        [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
    }
}

# Set node-specific variables
$env:NODE_ID = "my-node-01"
$env:NODE_STORAGE_PATH = ".\data\node1"
$env:NODE_HTTP_PORT = "8081"

# Jalankan DSDN node
.\target\release\dsdn-node.exe env
```

### 7.3 Expected Output

Jika berhasil, Anda akan melihat output seperti ini:

```
═══════════════════════════════════════════════════════════════
               DSDN Node (Mainnet Ready)
═══════════════════════════════════════════════════════════════
Node ID:      my-dsdn-node-01
Config Mode:  env
DA Network:   mainnet
DA Endpoint:  http://localhost:26658
Storage Path: ./data/node
HTTP Port:    8081
═══════════════════════════════════════════════════════════════
Connecting to Celestia DA...
🔍 DA health check (attempt 1/3)
health check completed status=Healthy network_height=9369597 local_height=0 latency_ms=383
✅ DA layer healthy
Initializing storage at ./data/node
🚀 Starting DA follower...
🏥 Health endpoint available at http://0.0.0.0:8081/health
╔═══════════════════════════════════════════════════════════════╗
║  INVARIANT: Node receives ALL commands via DA events ONLY    ║
║  Node does NOT accept instructions from Coordinator via RPC  ║
╚═══════════════════════════════════════════════════════════════╝

Node running. Press Ctrl+C to shutdown.
DA follower started for node my-dsdn-node-01
```

### 7.4 Running as a Service (Linux)

Untuk production, jalankan sebagai systemd service:

**/etc/systemd/system/celestia-light.service:**
```ini
[Unit]
Description=Celestia Light Node
After=network.target

[Service]
Type=simple
User=dsdn
ExecStart=/usr/local/bin/celestia light start --core.ip consensus.celestia.org --p2p.network celestia
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**/etc/systemd/system/dsdn-node.service:**
```ini
[Unit]
Description=DSDN Storage Node
After=network.target celestia-light.service
Requires=celestia-light.service

[Service]
Type=simple
User=dsdn
WorkingDirectory=/opt/dsdn
EnvironmentFile=/opt/dsdn/.env.mainnet
Environment="NODE_ID=my-node-01"
Environment="NODE_STORAGE_PATH=/var/lib/dsdn/data"
Environment="NODE_HTTP_PORT=8081"
ExecStart=/opt/dsdn/dsdn-node env
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable dan start:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable celestia-light dsdn-node
sudo systemctl start celestia-light
sudo systemctl start dsdn-node
```

---

## 8. Verifikasi & Monitoring

### 8.1 Health Check Endpoints

**Node Health:**
```bash
curl http://localhost:8081/health
```

**Expected Response:**
```json
{
  "status": "healthy",
  "da_available": true,
  "da_health": "Ok(Healthy)",
  "node_id": "my-dsdn-node-01",
  "uptime_seconds": 3600
}
```

### 8.2 Celestia Light Node Status

```bash
# Check sync status
curl -s http://localhost:26658/head | jq '.header.height'
```

### 8.3 Log Analysis

```bash
# Follow logs (systemd)
journalctl -u dsdn-node -f

# Grep for errors
journalctl -u dsdn-node | grep -i error
```

---

## 9. Troubleshooting

### 9.1 DA Connection Issues

**Error:** `DA layer unavailable`

**Penyebab:**
1. Celestia light node tidak running
2. Auth token invalid/expired
3. Network connectivity issues

**Solusi:**
1. Pastikan light node running: `ps aux | grep celestia`
2. Regenerate auth token: `celestia light auth admin --p2p.network celestia`
3. Check network: `curl http://localhost:26658/head`

---

**Error:** `auth error: invalid token`

**Solusi:**
1. Generate token baru dari light node yang SEDANG RUNNING
2. Update `DA_AUTH_TOKEN` di `.env.mainnet`
3. Restart DSDN node

---

### 9.2 Storage Issues

**Error:** `No space left on device`

**Solusi:**
1. Check disk space: `df -h`
2. Expand storage atau pindah ke disk lebih besar
3. Update `NODE_STORAGE_PATH` ke disk dengan space cukup

---

### 9.3 Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `NODE_ID environment variable not set` | Missing env var | Set NODE_ID sebelum run |
| `Production validation failed` | Invalid mainnet config | Check DA_AUTH_TOKEN dan DA_NETWORK |
| `connection refused` | Light node not running | Start celestia light node |
| `namespace mismatch` | Wrong namespace | Use official DA_NAMESPACE |

---

## 10. FAQ

### Q: Apakah saya harus menjalankan Celestia light node sendiri?

**A:** Ya, setiap node operator WAJIB menjalankan Celestia light node sendiri. Ini untuk:
- Decentralization
- Independensi (tidak bergantung pada pihak ketiga)
- Verifiability (Anda bisa verify semua data sendiri)

---

### Q: Berapa biaya menjalankan node per bulan?

**A:** Estimasi untuk Full Node Reguler:
- Listrik: Rp 100,000 - 300,000
- Internet: Rp 200,000 - 500,000 (jika dedicated)
- Total: ~Rp 300,000 - 800,000/bulan

---

### Q: Berapa reward yang bisa didapat?

**A:** Tergantung pada:
- Kapasitas node Anda
- Jumlah workload yang di-serve
- Harga token $NUSA

Estimasi: Node dengan 50 pelanggan aktif bisa dapat ~661 $NUSA/bulan (~Rp 6.6 juta dengan asumsi 1 $NUSA = Rp 10.000).

---

### Q: Apakah data saya aman secara hukum?

**A:** Ya. DSDN menggunakan enkripsi end-to-end dimana:
- Node tidak memiliki kunci dekripsi
- Node tidak bisa membaca isi data
- Sesuai dengan UU ITE dan prinsip safe harbor

---

### Q: Apa yang terjadi jika node saya offline?

**A:** 
- < 12 jam: Tidak ada penalty
- > 12 jam: Slashing 0.5% dari stake
- Data akan di-replicate ke node lain untuk menjaga RF=3

---

### Q: Bisakah saya menjalankan multiple nodes?

**A:** Ya, tapi:
- Setiap node harus punya NODE_ID berbeda
- Setiap node harus stake terpisah
- Anti-self-dealing tetap berlaku

---

### Q: Di mana saya bisa dapat bantuan?

**A:** 
- Discord: [DSDN Community](https://discord.gg/dsdn)
- Telegram: [@DSDNNetwork](https://t.me/dsdnnetwork)
- GitHub Issues: [dsdn-network/dsdn](https://github.com/dsdn-network/dsdn/issues)

---

## Appendix A: Quick Start Checklist

```
□ Hardware memenuhi minimum requirements
□ Celestia light node terinstall
□ Celestia light node running dan synced
□ Auth token di-generate
□ .env.mainnet dikonfigurasi dengan benar
□ Storage path memiliki cukup space
□ DSDN node binary siap
□ Node berhasil start tanpa error
□ Health endpoint accessible
□ Stake requirement terpenuhi (untuk production)
```

---

## Appendix B: Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DA_RPC_URL` | ✅ | - | Celestia light node RPC URL |
| `DA_NAMESPACE` | ✅ | - | DSDN namespace (58 hex chars) |
| `DA_AUTH_TOKEN` | ✅ | - | Celestia auth token |
| `DA_NETWORK` | ✅ | mainnet | Network identifier |
| `DA_TIMEOUT_MS` | ❌ | 30000 | Operation timeout |
| `DA_RETRY_COUNT` | ❌ | 3 | Retry attempts |
| `DA_RETRY_DELAY_MS` | ❌ | 1000 | Delay between retries |
| `NODE_ID` | ✅ | - | Unique node identifier |
| `NODE_STORAGE_PATH` | ✅ | - | Data storage directory |
| `NODE_HTTP_PORT` | ✅ | - | Health/metrics HTTP port |

---

## Appendix C: Network Information

### Celestia Mainnet

| Parameter | Value |
|-----------|-------|
| Chain ID | celestia |
| Consensus RPC | consensus.celestia.org |
| P2P Network | celestia |
| Block Explorer | https://celenium.io |

### DSDN Mainnet

| Parameter | Value |
|-----------|-------|
| Namespace | `000000000000000000000000000000000000000064736e6e0000000000` |
| Token | $NUSA |
| Max Supply | 300,000,000 $NUSA |

---

**Document Version:** 1.0.0  
**Last Updated:** January 2026  
**Maintained by:** DSDN Foundation

---

