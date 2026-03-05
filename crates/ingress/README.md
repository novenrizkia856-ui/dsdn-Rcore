# DSDN Ingress Crate

HTTP gateway untuk akses data DSDN. Ingress menerima request dari client, merutekan ke storage node berdasarkan placement information dari DA layer, dan menyediakan economic endpoints untuk reward claims, receipt status, dan fraud proof submissions.

## Architecture

```text
Client
   │
   ▼
┌──────────────────────────────────────────────────────────────────────┐
│                           INGRESS                                    │
│  ┌────────────┐  ┌───────────┐  ┌────────────────┐  ┌────────────┐ │
│  │ Rate Limit │→ │  Routing  │→ │    Fallback    │→ │  Economic  │ │
│  └────────────┘  └───────────┘  └────────────────┘  └────────────┘ │
│         │              │               │                    │        │
│         ▼              ▼               ▼                    ▼        │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                    DA Router (Cache)                             ││
│  │   • Node Registry    • Chunk Placements    • Event Logger       ││
│  └─────────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────────┘
         │                              │                    │
         ▼                              ▼                    ▼
   ┌──────────┐                  ┌───────────┐       ┌──────────────┐
   │   Node   │                  │ Celestia  │       │ Chain Layer  │
   │ (Storage)│                  │    DA     │       │  (Rewards)   │
   └──────────┘                  └───────────┘       └──────────────┘
```

## Economic System Overview

The ingress economic system enables nodes to claim rewards for completed workloads via a validated, auditable pipeline:

```text
dispatch → execute → receipt → claim → reward → DA log

1. Node executes workload assigned by coordinator
2. Coordinator generates receipt (TSS-signed via FROST)
3. Client submits claim via POST /claim
4. Ingress validates inputs (hex format, length, sanitization)
5. ChainForwarder forwards to chain (with retry + timeout)
6. Chain verifies receipt and distributes reward:
   • 70% → Node operator
   • 20% → Validator
   • 10% → Treasury
7. ReceiptEventLogger records audit events to DA layer
```

## Endpoint Reference

### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/object/:hash` | GET | Fetch object by chunk hash |
| `/health` | GET | Health check (returns JSON status) |
| `/ready` | GET | Readiness probe (strict conditions) |
| `/metrics` | GET | Prometheus metrics |
| `/fallback/status` | GET | Fallback status (source of truth) |

### Economic Endpoints

| Endpoint | Method | Description | Rate Limit |
|----------|--------|-------------|------------|
| `POST /claim` | POST | Submit reward claim | 10 req/min/IP |
| `GET /receipt/:hash` | GET | Query single receipt status | 60 req/min/IP |
| `POST /receipts/status` | POST | Batch query up to 100 hashes | 60 req/min/IP |
| `GET /rewards/:address` | GET | Query reward balance by address | 60 req/min/IP |
| `GET /rewards/validators` | GET | List all validator rewards | 60 req/min/IP |
| `GET /rewards/treasury` | GET | Query treasury statistics | 60 req/min/IP |
| `POST /fraud-proof` | POST | Submit fraud proof (placeholder) | 10 req/min/IP |
| `GET /fraud-proofs` | GET | List all fraud proof submissions | 60 req/min/IP |

## Example Curl Requests

### Submit a Claim

```bash
curl -X POST http://localhost:8088/claim \
  -H "Content-Type: application/json" \
  -d '{
    "receipt_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "submitter_address": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "receipt_data": [1, 2, 3, 4]
  }'
```

**Response (200):**
```json
{ "success": true, "message": "claim accepted (stub)" }
```

### Query Receipt Status

```bash
curl http://localhost:8088/receipt/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

**Response (200):**
```json
{
  "receipt_hash": "aaaa...aaaa",
  "status": "finalized",
  "reward_amount": 10000,
  "node_id": "node-1",
  "workload_type": "compute",
  "submitted_at": 1700000000
}
```

### Batch Receipt Status

```bash
curl -X POST http://localhost:8088/receipts/status \
  -H "Content-Type: application/json" \
  -d '{ "hashes": ["aaaa...64hex...", "bbbb...64hex..."] }'
```

### Query Reward Balance

```bash
curl http://localhost:8088/rewards/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
```

**Response (200):**
```json
{
  "address": "bbbb...bbbb",
  "balance": 50000,
  "pending_rewards": 3000,
  "claimed_rewards": 10000,
  "node_earnings": 0,
  "is_validator": true,
  "is_node": false
}
```

### List Validator Rewards

```bash
curl http://localhost:8088/rewards/validators
```

### Query Treasury

```bash
curl http://localhost:8088/rewards/treasury
```

### Submit Fraud Proof

```bash
curl -X POST http://localhost:8088/fraud-proof \
  -H "Content-Type: application/json" \
  -d '{
    "receipt_hash": "aaaa...64hex...",
    "proof_type": "execution_mismatch",
    "proof_data": [1, 2, 3],
    "submitter_address": "cccc...40hex...",
    "challenge_id": null
  }'
```

**Response (200):**
```json
{
  "accepted": true,
  "fraud_proof_id": "fp-aaaaaaaa-cccccccc-00000000",
  "message": "fraud proof accepted (placeholder)",
  "note": "placeholder — not processed until Tahap 18.8"
}
```

### List Fraud Proofs

```bash
curl http://localhost:8088/fraud-proofs
```

## Error Handling

| Error | HTTP Status | Description |
|-------|-------------|-------------|
| Invalid hex format | 400 | Hash/address contains non-hex characters |
| Invalid length | 400 | Hash not 64 chars or address not 40 chars |
| Empty field | 400 | Required field is empty |
| Invalid proof type | 400 | proof_type not in allowed values |
| Batch limit exceeded | 400 | More than 100 hashes in batch query |
| Rate limit exceeded | 429 | Too many requests per IP |
| Chain forwarding error | 500 | Internal chain RPC failure |
| Lock error | 500 | Internal state lock poisoned |
| Chunk not found | 404 | Chunk hash not in placement data |
| No available nodes | 503 | All storage nodes inactive |
| All nodes failed | 502 | All fallback attempts failed |
| Timeout | 504 | Request timed out |

### Validation Rules

**Receipt Hash**: Exactly 64 hex characters (a-f, A-F, 0-9). No whitespace. No `0x` prefix. Trimmed before validation.

**Address**: Exactly 40 hex characters. Same rules as hash.

**Proof Type**: Must be one of: `execution_mismatch`, `invalid_commitment`, `resource_inflation`.

**Proof Data / Receipt Data**: Must not be empty.

**Batch Hashes**: Min 1, max 100. All hashes validated before any query executes.

## Rate Limiting

Token bucket algorithm with per-IP enforcement:

- **Mutation endpoints** (`POST /claim`, `POST /fraud-proof`): **10 requests/minute per IP**, burst 10
- **Query endpoints** (all GET + `POST /receipts/status`): **60 requests/minute per IP**, burst 60
- **Global**: 1000 req/s, burst 2000

Exceeding limits returns HTTP 429 with `Retry-After` header.

## Economic Event Logging

All receipt economic events are recorded to an audit-safe DA log via `ReceiptEventLogger`:

**Event Types:**
- `ClaimSubmitted` — logged when a claim request passes validation
- `ClaimAccepted` — logged when chain accepts the claim
- `ClaimRejected` — logged when chain rejects or forwarding fails
- `ChallengeStarted` — logged when a challenge period begins
- `FraudProofReceived` — logged when a fraud proof is submitted

**Publish Flow:**
1. Events buffered in deterministic insertion order
2. On flush, serialized to deterministic JSON
3. Published via `EventPublisher` to DA layer
4. If publisher unavailable or fails → fallback to append-only local file
5. Buffer only cleared after successful publish or file write (no data loss)

**Timestamps:** All events use Unix epoch seconds (consistent across all variants).

## Fraud Proof Placeholder Notice

**The `/fraud-proof` and `/fraud-proofs` endpoints are placeholders only.**

Submissions are accepted and logged, but NOT processed. No verification, arbitration, slashing, or challenge resolution occurs.

Full fraud proof processing will be implemented in **Tahap 18.8**.

## Modules

| Module | Description |
|--------|-------------|
| `da_router` | DA-aware routing with cache |
| `routing` | Request routing logic (fallback-aware) |
| `fallback` | Fallback & retry mechanisms |
| `fallback_health` | FallbackHealthInfo struct |
| `alerting` | Alert hooks for fallback events |
| `metrics` | Observability & Prometheus metrics |
| `rate_limit` | Rate limiting middleware (token bucket) |
| `economic_handlers` | Receipt, reward, fraud proof, and claim handlers |
| `economic_validation` | Input validation, sanitization, chain forwarding |
| `receipt_event_logger` | DA audit logging for receipt economic events |

## Thread Safety

All components thread-safe: `parking_lot::RwLock`, `std::sync::Mutex`, `AtomicU64`/`AtomicBool`, `Arc`. No global mutable state.

## Testing

```bash
# Unit tests
cargo test --package dsdn-ingress

# Integration tests (economic endpoints)
cargo test --package dsdn-ingress --test economic_endpoint_tests

# All tests
cargo test --package dsdn-ingress --all-targets
```

## License

Copyright DSDN Project. All rights reserved.