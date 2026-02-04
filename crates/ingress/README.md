# DSDN Ingress Crate

HTTP gateway untuk akses data DSDN. Ingress menerima request dari client dan merutekan ke storage node berdasarkan placement information dari DA (Data Availability) layer.

## Architecture

```text
Client
   │
   ▼
┌──────────────────────────────────────────────────────┐
│                    INGRESS                           │
│  ┌────────────┐  ┌───────────┐  ┌────────────────┐  │
│  │ Rate Limit │→ │  Routing  │→ │    Fallback    │  │
│  └────────────┘  └───────────┘  └────────────────┘  │
│         │              │               │             │
│         ▼              ▼               ▼             │
│  ┌────────────────────────────────────────────────┐ │
│  │              DA Router (Cache)                 │ │
│  │   • Node Registry                              │ │
│  │   • Chunk Placements                           │ │
│  └────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────┘
         │                              │
         ▼                              ▼
   ┌──────────┐                  ┌───────────┐
   │   Node   │                  │ Celestia  │
   │ (Storage)│                  │    DA     │
   └──────────┘                  └───────────┘
```

## Endpoints

| Endpoint | Method | Deskripsi |
|----------|--------|-----------|
| `/object/:hash` | GET | Fetch object by chunk hash |
| `/health` | GET | Health check (returns JSON status) |
| `/ready` | GET | Readiness probe (strict conditions) |
| `/metrics` | GET | Prometheus metrics |

## Request Flow

1. **Rate Limiting**: Request dicek terhadap rate limit (per-IP, per-API-key, global)
2. **Routing Decision**: DARouter mencari placement untuk chunk hash
3. **Node Selection**: Pilih node target berdasarkan:
   - Zone affinity (prefer same zone)
   - Node health (hanya active nodes)
   - Deterministic tie-breaker (sorted by node ID)
4. **Fetch**: Request dikirim ke target node
5. **Fallback**: Jika gagal, coba node berikutnya
6. **Response**: Return data ke client

## Modules

### da_router
DA-aware routing dengan cache. Sumber kebenaran adalah DA layer, cache hanya untuk performa.

- `DARouter`: Main router struct
- `CachedRoutingState`: Cache node registry dan chunk placements
- `RoutingDataSource` trait: Abstraksi sumber data

### routing
Request routing logic.

- `RoutingDecision`: Hasil keputusan routing
- `RoutingStrategy`: ZoneAffinity, RoundRobin, LeastLoaded
- `ClientInfo`: Informasi client untuk routing

### fallback
Fallback dan retry logic dengan circuit breaker.

- `FallbackManager`: Manages fallback attempts
- `CircuitState`: Closed, Open, HalfOpen
- Circuit breaker: threshold=5, backoff=30s

### rate_limit
Token bucket rate limiter.

- `RateLimiter`: Main limiter struct
- `LimitConfig`: Per-IP, per-API-key, atau global
- Middleware: Axum middleware untuk enforcement

### metrics
Observability dengan Prometheus metrics.

- `IngressMetrics`: Counter, Histogram, Gauge
- `TraceId`: Unique per-request identifier
- `/metrics` endpoint: Prometheus exposition format

## DA Integration

**PENTING**: Ingress TIDAK query Coordinator untuk placement decision.

Semua routing berdasarkan:
- State yang di-derive dari DA (Celestia)
- Cache yang di-refresh secara periodik
- Events dari DA untuk cache invalidation

Ini memastikan:
- Single source of truth (DA)
- Consistency dengan blockchain state
- Auditability dari routing decisions

## Health & Readiness

### Health (`/health`)
Returns JSON dengan status:
- `da_connected`: DA layer connectivity
- `da_last_sequence`: Last processed DA sequence
- `cached_nodes`: Jumlah node dalam cache
- `cached_placements`: Jumlah placement dalam cache
- `cache_age_ms`: Umur cache
- `coordinator_reachable`: Coordinator connectivity
- `healthy_nodes`: Jumlah active nodes
- `total_nodes`: Total nodes dalam registry

### Readiness (`/ready`)
Returns 200 OK hanya jika:
- Coordinator reachable
- Cache sudah diisi (jika DA router aktif)
- Ada minimal 1 healthy node

## Configuration

Environment variables:
- `COORD_BASE_URL`: Coordinator base URL (default: `http://localhost:8080`)
- `DA_ROUTER_TTL_MS`: Cache TTL dalam milliseconds (default: 30000)

## Apa yang TIDAK Dilakukan Ingress

1. **TIDAK menyimpan data**: Ingress hanya gateway, bukan storage
2. **TIDAK memiliki state authoritative**: Semua state dari DA
3. **TIDAK query Coordinator untuk placement**: Hanya DA
4. **TIDAK membuat keputusan tanpa data**: Error jika cache kosong
5. **TIDAK bypass rate limiting**: Semua request dicek
6. **TIDAK assume node health**: Harus eksplisit dari data

## Error Handling

| Error | HTTP Status | Deskripsi |
|-------|-------------|-----------|
| Chunk not found | 404 | Chunk tidak ada dalam placement |
| No available nodes | 503 | Semua node untuk chunk inactive |
| Rate limit exceeded | 429 | Request melebihi limit |
| All nodes failed | 502 | Semua fallback gagal |
| Timeout | 504 | Request timeout |

## Thread Safety

Semua komponen thread-safe:
- `parking_lot::RwLock` untuk cache state
- `AtomicU64` untuk counters
- Arc untuk shared ownership
- No global mutable state

## Testing

```bash
# Unit tests
cargo rustsp test --package dsdn-ingress

# Integration tests
cargo rustsp test --package dsdn-ingress --test routing_test
```

## License

Copyright DSDN Project. All rights reserved.