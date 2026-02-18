# dsdn-proto

**Canonical schema definitions and deterministic serialization for the DSDN Data Availability layer.**

`dsdn-proto` is the single source of truth for every data structure that crosses a trust boundary in DSDN. Coordinators, storage nodes, and validators all depend on this crate to produce and verify byte-identical encodings of DA events, fallback operations, threshold signatures, and reconciliation reports.

---

## Role in the DSDN Architecture

DSDN (Distributed Storage and Data Network) uses a three-plane architecture where the **control plane** publishes authoritative events to a Data Availability layer (Celestia). Every participant in the network — coordinators that emit events, storage nodes that consume them, and validators that verify state transitions — must agree on the exact binary representation of those events.

`dsdn-proto` enforces that agreement. It sits below every other crate in the dependency graph and exports:

- The event schemas that define what the control plane can say.
- The encoding functions that turn those schemas into deterministic bytes.
- The hashing functions that produce the commitments validators check.
- The fallback and reconciliation types that keep the system running when Celestia is unavailable.
- The TSS (Threshold Signature Scheme) protocol messages that enable committee-based signing.

```
                         ┌─────────────────┐
                         │   Celestia DA   │
                         │  (Primary DA)   │
                         └────────┬────────┘
                                  │
               ┌─────────────────┼──────────────────┐
               │                 │                   │
               ▼                 ▼                   ▼
      ┌────────────────┐ ┌────────────────┐ ┌────────────────┐
      │  Coordinator   │ │ Storage Nodes  │ │   Validators   │
      │  (event emit)  │ │ (event consume)│ │ (event verify) │
      └───────┬────────┘ └───────┬────────┘ └───────┬────────┘
              │                  │                   │
              └─────────────────┼───────────────────┘
                                │
                    ┌───────────┴───────────┐
                    │      dsdn-proto       │
                    │  (shared contracts)   │
                    └───────────────────────┘
```

No crate in DSDN may define its own serialization of a DA event. All wire formats originate here.

---

## Modules

### `da_event` — Core DA Event Schema

Defines the `DAEvent` enum and all supporting types for normal storage operations posted to Celestia.

| Type | Purpose |
|------|---------|
| `DAEvent` | Top-level enum: `NodeRegistered`, `ChunkDeclared`, `ReplicaAdded`, `ReplicaRemoved`, `DeleteRequested` |
| `DAEventEnvelope` | Wire-format wrapper with version, sequence, checksum, and payload |
| `DAEventType` | Discriminant enum for routing without deserializing the payload |
| `BlobRef` | Pointer to a specific blob on Celestia (height + namespace + index + commitment) |
| `BlobMetadata` | Size, event count, and sequence range for a blob |
| `ReplicaRemovalReason` | Why a replica was removed (`NodeOffline`, `Rebalancing`, `Corruption`, etc.) |
| `DeleteReason` | Why a chunk deletion was requested |

Every `DAEvent` variant carries an explicit `version: u8` field and a caller-provided `timestamp_ms: u64`. No implicit defaults, no auto-generated timestamps.

The `DAEventEnvelope` adds integrity verification: the `checksum` field holds a SHA3-256 digest of the serialized payload. After calling `decode()`, consumers **must** call `verify_checksum()` before trusting the contents.

### `encoding` — Deterministic Serialization & Hashing

All encode/decode functions share a single bincode configuration to guarantee bitwise-identical output across platforms:

| Property | Value |
|----------|-------|
| Format | bincode |
| Byte order | Little-endian |
| Integer encoding | Fixed-width |
| String encoding | Length-prefixed (u64) |
| Enum encoding | u32 discriminant + payload |

**Core API:**

| Function | Input → Output |
|----------|----------------|
| `encode_event` | `&DAEvent` → `Vec<u8>` |
| `decode_event` | `&[u8]` → `Result<DAEvent, DAError>` |
| `compute_event_hash` | `&DAEvent` → `[u8; 32]` (SHA3-256) |
| `batch_encode` | `&[DAEvent]` → `Vec<u8>` (length-prefixed concatenation) |
| `batch_decode` | `&[u8]` → `Result<Vec<DAEvent>, DAError>` |
| `encode_fallback_event` | `&FallbackEvent` → `Vec<u8>` |
| `decode_fallback_event` | `&[u8]` → `Result<FallbackEvent, DecodeError>` |
| `encode_pending_blob` | `&PendingBlob` → `Vec<u8>` |
| `decode_pending_blob` | `&[u8]` → `Result<PendingBlob, DecodeError>` |
| `compute_fallback_event_hash` | `&FallbackEvent` → `[u8; 32]` |
| `compute_pending_blob_hash` | `&PendingBlob` → `[u8; 32]` |
| `verify_fallback_event_hash` | `(&FallbackEvent, &[u8; 32])` → `bool` |

**Determinism guarantees:**

- `encode(x) == encode(x)` for identical input (bitwise).
- `decode(encode(x)) == x` for all valid `x` (roundtrip).
- `hash(x) == hash(x)` for identical input (bitwise).

The hash pipeline is always: `struct → encode → SHA3-256 → [u8; 32]`. Hashes are never computed directly from struct fields; they are always computed from the serialized representation, ensuring that any two implementations that agree on serialization will also agree on hashes.

**Batch format:**

```
[event_count: u64 LE][event_1_len: u64 LE][event_1_bytes]...[event_N_len: u64 LE][event_N_bytes]
```

Event order is preserved. The format is self-describing: a reader can skip events it does not understand by reading the length prefix and advancing.

### `da_health` — Health Status & Error Types

Types for monitoring the DA layer connection.

| Type | Purpose |
|------|---------|
| `DAHealthStatus` | `Healthy`, `Degraded`, `Unavailable`, `Syncing` — each with relevant metadata |
| `DAError` | `ConnectionFailed`, `BlobNotFound`, `InvalidBlob`, `NamespaceMismatch`, `DecodeFailed`, `Timeout`, `RateLimited` |

`DAError` implements `std::error::Error` and `Display`. The `RateLimited` variant carries a `retry_after_ms` field so callers can implement backoff without guessing.

### `fallback_event` — DA Resilience Events (Spec 14A.1A)

When Celestia becomes unavailable, DSDN activates a fallback DA layer (either a Validator Quorum or an Emergency fallback). This module defines the events that track that lifecycle.

| Type | Purpose |
|------|---------|
| `FallbackEvent` | Enum: `FallbackActivated`, `FallbackDeactivated`, `ReconciliationStarted`, `ReconciliationCompleted` |
| `FallbackActivated` | Carries reason, last Celestia height, activation timestamp, fallback type |
| `FallbackDeactivated` | Carries recovery height, blobs reconciled, deactivation timestamp, downtime duration |
| `ReconciliationStarted` | Pending blob count, start timestamp, source DA identifier |
| `ReconciliationCompleted` | Reconciled/failed counts, completion timestamp, duration |
| `FallbackType` | `ValidatorQuorum` or `Emergency` |

Each `FallbackEvent` variant carries a `version: u32` field for schema evolution. The current schema version is `FALLBACK_EVENT_SCHEMA_VERSION = 1`.

**Lifecycle:**

```
Normal Operation
      │
      ▼ (Celestia unavailable)
FallbackActivated { reason, celestia_last_height, fallback_type }
      │
      │  (blobs stored to fallback DA, tracked as PendingBlob)
      │
      ▼ (Celestia recovers)
ReconciliationStarted { pending_count, source_da }
      │
      │  (each PendingBlob posted to Celestia)
      │
      ▼
ReconciliationCompleted { reconciled_count, failed_count, duration_ms }
      │
      ▼
FallbackDeactivated { celestia_recovery_height, blobs_reconciled, downtime_duration_secs }
      │
      ▼
Normal Operation (resumed)
```

### `pending_blob` — Blobs Awaiting Reconciliation (Spec 14A.1A.6)

During a fallback period, every blob written to the fallback DA is recorded as a `PendingBlob` so it can be replayed to Celestia once connectivity is restored.

| Field | Type | Purpose |
|-------|------|---------|
| `data` | `Vec<u8>` | Raw blob payload |
| `original_sequence` | `u64` | Ordering key from the original event stream |
| `source_da` | `String` | Which fallback DA layer stored this blob |
| `received_at` | `u64` | Unix timestamp when the blob was received |
| `retry_count` | `u32` | How many times reconciliation has been attempted |
| `commitment` | `Option<[u8; 32]>` | Optional hash commitment for integrity verification |

A blob is considered expired when `retry_count > MAX_RETRY_COUNT` (currently 3). The `is_expired()` method is deterministic — it depends only on the struct's own data, not on wall-clock time.

`PendingBlob` also provides `size_bytes()` which returns `data.len()`, and its hash is computed through the same `encode → SHA3-256` pipeline as all other proto types.

### `reconcile_report` — Reconciliation Results (Spec 14A.1A.5)

After a reconciliation pass, the system produces a `ReconcileReport` summarizing what happened to each pending blob.

| Type | Purpose |
|------|---------|
| `ReconcileReport` | Top-level summary: total pending, reconciled, failed, skipped, timestamps, and per-blob details |
| `ReconcileDetail` | Per-blob result: sequence, original height, Celestia height (if posted), status, error message |
| `ReconcileStatus` | `Success`, `Failed`, `Skipped`, `Pending` |

The report is designed for both machine consumption (status enums, counts) and human debugging (error strings, per-blob details).

### `consistency_report` — Post-Recovery Verification (Spec 14A.1A.7)

After fallback deactivation, the system can run a consistency check comparing the fallback DA's records against what actually landed on Celestia.

| Type | Purpose |
|------|---------|
| `ConsistencyReport` | Heights compared, consistency flag, list of mismatches, timing |
| `ConsistencyMismatch` | Sequence number, hashes from both layers, mismatch type |
| `MismatchType` | `Missing`, `HashMismatch`, `SequenceGap`, `Duplicate` |

If `is_consistent` is `true`, the `mismatches` vector is empty. If `false`, each mismatch entry pinpoints exactly which blob diverged and how.

### `tss` — Threshold Signature Scheme Protocol Messages (Spec 14A.2B)

Defines the wire-format messages for DSDN's FROST-based threshold signing protocol, used by the coordinator committee. The module is split into four sub-modules, each with its own types, validation, encoding, and error handling.

```
                      ┌──────────────────────┐
                      │  Coordinator Nodes   │
                      │  (TSS Participants)  │
                      └──────────┬───────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                       │
          ▼                      ▼                       ▼
  ┌────────────────┐   ┌────────────────┐     ┌────────────────┐
  │      DKG       │   │    Signing     │     │   Committee    │
  │   (Phase 1)    │──▶│   (Phase 2)    │──▶  │  Coordination  │
  └────────┬───────┘   └────────┬───────┘     └────────┬───────┘
           │                    │                      │
           ▼                    ▼                      ▼
  ┌────────────────┐   ┌────────────────┐     ┌────────────────┐
  │  Round1Package │   │ SigningRequest │     │CoordinatorMember│
  │  Round2Package │   │   Commitment   │     │CoordinatorComm. │
  │   DKGResult    │   │  PartialSig    │     │  ReceiptData   │
  └────────────────┘   │  AggregateSig  │     │ThresholdReceipt│
                       └────────────────┘     └────────────────┘
```

#### `tss::types` — Base Wrapper Types

Two fixed-size byte wrappers used throughout the TSS module. Both enforce explicit length validation (no auto-padding, no truncation, no panic).

| Type | Size | Used For |
|------|------|----------|
| `BytesWrapper` | 32 bytes | Identifiers, hashes, public keys |
| `SignatureBytes` | 64 bytes | FROST signatures (R ‖ s format), EdDSA signatures |

Both provide `from_array()` (infallible, exact size), `from_vec()` (no validation), `to_array()` (returns `Option` — `None` if wrong length), and `into_vec()`. Both implement `Default` (zero-filled at correct size), `Serialize`/`Deserialize`, `Clone`, `Eq`, `Send + Sync`.

#### `tss::dkg` — Distributed Key Generation (Spec 14A.2B.1.22–24)

Implements the two-round Pedersen DKG protocol messages. Round 1 is broadcast; Round 2 is peer-to-peer with encrypted shares.

**Messages:**

| Struct | Fields | Purpose |
|--------|--------|---------|
| `DKGRound1PackageProto` | `session_id` (32B), `participant_id` (32B), `commitment` (32B), `proof` (64B) | Broadcast: Pedersen commitment + Schnorr proof of knowledge |
| `DKGRound2PackageProto` | `session_id` (32B), `from_participant` (32B), `to_participant` (32B), `encrypted_share` (>0B) | P2P: Encrypted secret share for a specific recipient |
| `DKGResultProto` | `session_id` (32B), `group_pubkey` (32B), `participant_pubkeys` (each 32B), `threshold`, `success`, `error_message` | Final result with group key or failure reason |

`DKGResultProto` has two constructors: `success(...)` and `failure(session_id, error_message)`. The failure path zeroes out `group_pubkey`, `participant_pubkeys`, and `threshold`, and sets `error_message` to `Some(...)`.

**Validation rules** (enforced by `.validate()`):

- All identifier/key fields must be exactly their declared size.
- `encrypted_share` must not be empty.
- Success results: `threshold > 0`, `threshold <= participant_pubkeys.len()`, `error_message == None`.
- Failure results: `error_message.is_some()`.

**Error types:** `ValidationError` (14 variants covering every field-length and semantic check) and `DecodeError` (empty input, deserialization failure, post-decode validation failure).

**Protocol flow:**

```
  Participant A         Coordinator         Participant B
       │                     │                     │
       │──Round1Package ────▶│                     │
       │                     │◀────Round1Package───│
       │                     │                     │
       │◀── Broadcast R1 ───│──── Broadcast R1 ──▶│
       │                     │                     │
       │──Round2Package ────▶│                     │
       │  (encrypted share)  │◀────Round2Package───│
       │                     │                     │
       │◀── Deliver R2 ─────│───── Deliver R2 ───▶│
       │                     │                     │
       │──────DKGResult ────▶│                     │
       │                     │◀──────DKGResult ────│
       │                     │                     │
       │◀──GroupPublicKey ───│────GroupPublicKey──▶│
```

#### `tss::signing` — Threshold Signing (Spec 14A.2B.1.25–27)

Implements the four-message FROST signing protocol: request → commitment → partial signature → aggregation.

**Messages:**

| Struct | Fields | Purpose |
|--------|--------|---------|
| `SigningRequestProto` | `session_id` (32B), `message` (variable), `message_hash` (32B), `required_signers` (each 32B), `epoch`, `timeout_secs`, `request_timestamp` | Client's request to threshold-sign a message |
| `SigningCommitmentProto` | `session_id` (32B), `signer_id` (32B), `hiding` (32B), `binding` (32B), `timestamp` | Signer's nonce commitment (FROST Round 1) |
| `PartialSignatureProto` | `session_id` (32B), `signer_id` (32B), `signature_share` (32B), `commitment` (nested `SigningCommitmentProto`) | Signer's partial signature (FROST Round 2) |
| `AggregateSignatureProto` | `signature` (64B), `signer_ids` (each 32B, no duplicates), `message_hash` (32B), `aggregated_at` | Final FROST threshold signature |

**Validation highlights:**

- `SigningRequestProto`: `timeout_secs > 0`, `required_signers` not empty, no duplicate signers.
- `PartialSignatureProto`: validates both its own fields and the nested `commitment`.
- `AggregateSignatureProto`: `signature` must be exactly 64 bytes (R ‖ s), no duplicate `signer_ids`.

**Error types:** `SigningValidationError` and `SigningDecodeError`, parallel to the DKG error design.

**Protocol flow:**

```
  Client             Coordinator             Participants
     │                     │                      │
     │──SigningRequest ───▶│                      │
     │  (message_hash)     │───SigningRequest ───▶│
     │                     │                      │
     │                     │◀──Commitment ────────│
     │                     │   (hiding, binding)  │
     │                     │                      │
     │                     │──Broadcast Commits──▶│
     │                     │                      │
     │                     │◀──PartialSignature───│
     │                     │   (signature_share)  │
     │                     │                      │
     │◀─AggregateSig ─────│                      │
     │  (64B FROST sig)    │                      │
```

#### `tss::committee` — Committee Management & Receipts (Spec 14A.2B.1.28–29)

Manages the coordinator committee composition and provides receipt types for workload verification.

**Committee types:**

| Struct | Fields | Purpose |
|--------|--------|---------|
| `CoordinatorMemberProto` | `id` (32B), `validator_id` (32B), `pubkey` (32B), `stake` (>0), `joined_at` | Single committee member with stake weight |
| `CoordinatorCommitteeProto` | `members` (non-empty), `threshold`, `epoch`, `epoch_start`, `epoch_duration_secs` (>0), `group_pubkey` (32B) | Full committee: membership, threshold, epoch timing, group key |

Committee validation enforces: no duplicate member IDs, `threshold ∈ [1, members.len()]`, `epoch_duration_secs > 0`, all nested members valid.

**Receipt types:**

| Struct | Fields | Purpose |
|--------|--------|---------|
| `ReceiptDataProto` | `workload_id` (32B), `blob_hash` (32B), `placement` (each 32B), `timestamp`, `sequence`, `epoch` | Workload receipt: what was stored, where, when |
| `ThresholdReceiptProto` | `receipt_data`, `signature` (nested `AggregateSignatureProto`), `signer_ids` (each 32B), `epoch`, `committee_hash` (32B) | Committee-signed receipt with cross-validation |

`ThresholdReceiptProto` validation cross-checks: `signer_ids` must exactly match `signature.signer_ids`, `epoch` must match `receipt_data.epoch`, no duplicates in signer list.

`ReceiptDataProto` provides `compute_hash() → [u8; 32]` which is the binding commitment that the committee signs. This hash must be identical to the chain-side `ReceiptData::receipt_data_hash()`.

**Receipt flow:**

```
  Storage Node         Committee              Verifier
       │                   │                      │
       │──ReceiptData ───▶│                      │
       │  (workload_id,   │                      │
       │   blob_hash,     │──[threshold sign]───▶│
       │   placement)     │                      │
       │                  │                      │
       │◀─ThresholdRcpt──│                      │
       │  (aggregate_sig, │                      │
       │   committee_hash)│                      │
       │                  │                      │
       │──────────────────│──ThresholdReceipt──▶│
       │                  │                      │── verify()
```

#### TSS Field Size Constants

All cryptographic field sizes are defined as constants, enforced by validation, and must not change across versions.

| Constant | Bytes | Module | Used By |
|----------|-------|--------|---------|
| `SESSION_ID_SIZE` | 32 | dkg, signing | All session-scoped messages |
| `PARTICIPANT_ID_SIZE` | 32 | dkg | DKG round messages |
| `COMMITMENT_SIZE` | 32 | dkg | Pedersen commitments |
| `PROOF_SIZE` | 64 | dkg | Schnorr proofs |
| `GROUP_PUBKEY_SIZE` | 32 | dkg, committee | Group public key (DKG output) |
| `SIGNER_ID_SIZE` | 32 | signing | Signing participant IDs |
| `MESSAGE_HASH_SIZE` | 32 | signing | SHA3-256 of message to sign |
| `HIDING_SIZE` | 32 | signing | FROST hiding nonce |
| `BINDING_SIZE` | 32 | signing | FROST binding nonce |
| `SIGNATURE_SHARE_SIZE` | 32 | signing | Partial signature scalar |
| `FROST_SIGNATURE_SIZE` | 64 | signing | Final aggregate (R ‖ s) |
| `COORDINATOR_ID_SIZE` | 32 | committee | Committee member ID |
| `VALIDATOR_ID_SIZE` | 32 | committee | Validator identity |
| `PUBKEY_SIZE` | 32 | committee | TSS public key |
| `WORKLOAD_ID_SIZE` | 32 | committee | Receipt workload ID |
| `BLOB_HASH_SIZE` | 32 | committee | Receipt blob hash |
| `NODE_ID_SIZE` | 32 | committee | Receipt node placement |
| `COMMITTEE_HASH_SIZE` | 32 | committee | Committee identity hash |

#### TSS Encoding & Hash Functions

Every TSS message type has a symmetric `encode_*` / `decode_*` pair. Decode functions validate after deserialization — a malformed message that decodes successfully at the bincode level will still be rejected if field sizes are wrong.

| Function | Direction | Hash? |
|----------|-----------|-------|
| `encode_dkg_round1` / `decode_dkg_round1` | `DKGRound1PackageProto` ↔ bytes | `compute_dkg_round1_hash` |
| `encode_dkg_round2` / `decode_dkg_round2` | `DKGRound2PackageProto` ↔ bytes | — |
| `encode_dkg_result` / `decode_dkg_result` | `DKGResultProto` ↔ bytes | — |
| `encode_signing_request` / `decode_signing_request` | `SigningRequestProto` ↔ bytes | — |
| `encode_signing_commitment` / `decode_signing_commitment` | `SigningCommitmentProto` ↔ bytes | — |
| `encode_partial_signature` / `decode_partial_signature` | `PartialSignatureProto` ↔ bytes | — |
| `encode_aggregate_signature` / `decode_aggregate_signature` | `AggregateSignatureProto` ↔ bytes | `compute_aggregate_signature_hash` |
| `encode_committee` / `decode_committee` | `CoordinatorCommitteeProto` ↔ bytes | `compute_committee_hash` |
| `encode_receipt` / `decode_receipt` | `ThresholdReceiptProto` ↔ bytes | `compute_receipt_hash` |
| — | `ReceiptDataProto` (method) | `compute_hash()` |

Hash functions are only provided for types that serve as commitments or need to be referenced by digest (DKG Round 1 broadcasts, aggregate signatures, committees, receipts). All use the same `bincode → SHA3-256` pipeline.

---

## Encoding Consistency Across Types

Every serializable type in this crate — whether a `DAEvent`, a `FallbackEvent`, a `PendingBlob`, or a TSS message — uses the exact same bincode configuration. This is not a convention; it is enforced by having all encode functions call the same serialization path.

```
  DAEvent              FallbackEvent           PendingBlob            TSS Messages
     │                      │                      │                      │
     ▼                      ▼                      ▼                      ▼
encode_event()    encode_fallback_event()  encode_pending_blob()   encode_dkg_round1()
     │                      │                      │                      │
     └──────────────────────┼──────────────────────┼──────────────────────┘
                            │
                   ┌────────┴────────┐
                   │  Same bincode   │
                   │  Same SHA3-256  │
                   │  Same pipeline  │
                   └─────────────────┘
```

This matters because validators must be able to verify hashes across event types without special-casing. A hash is always `SHA3-256(bincode_serialize(value))`, regardless of the value's type.

---

## Transport Agnosticism

`dsdn-proto` has no dependency on any specific DA layer client, network transport, or RPC framework. It operates purely on `&[u8]` input and `Vec<u8>` / `[u8; 32]` output. This means:

- The same schemas work with Celestia, a validator quorum DA, or an emergency fallback DA.
- Consumers can wrap the encoded bytes in whatever transport they need (gRPC, HTTP, raw TCP) without touching the proto layer.
- Testing requires no network mocking — just bytes in, bytes out.

---

## Version Compatibility

Current proto version: **0.1** (`PROTO_VERSION`).

**Must not change (breaking):**

- Field names, order, and types within any struct or enum variant.
- The bincode encoding configuration (little-endian, fixed-width integers, length-prefixed strings).
- The hash algorithm (SHA3-256).
- The batch encoding format (u64 count + u64 length-prefixed entries).

**May be added (non-breaking):**

- New enum variants appended at the end.
- New struct fields with default values.

**Forward compatibility caveat:** A decoder from an older version will fail to deserialize messages containing unknown enum variants or fields. Use the `version` field present on every event to detect version mismatches before attempting decode.

---

## Test Coverage

The crate includes 554 unit tests across all modules:

| Module | Tests | Focus |
|--------|-------|-------|
| `da_event` | 26 | Enum construction, Display impls, field validation |
| `encoding` | 86 | Roundtrip determinism, batch encode/decode, hash stability, empty/edge inputs |
| `fallback_event` | 77 | All variants, Default impls, serde roundtrip, Display, edge cases |
| `pending_blob` | 30 | Expiry logic, size calculation, commitment handling, hash determinism |
| `reconcile_report` | 38 | Status variants, report construction, edge cases |
| `consistency_report` | 35 | Mismatch types, empty reports, large mismatch lists |
| `da_health` | 15 | All status/error variants, Display, Clone, Error trait |
| `tss::types` | 19 | BytesWrapper/SignatureBytes: construction, conversion, edge lengths, serde, Send+Sync |
| `tss::dkg` | 59 | Round1/Round2/Result validation, encode/decode roundtrip, hash determinism, failure paths |
| `tss::signing` | 78 | Request/Commitment/PartialSig/AggregateSig validation, duplicate detection, nested validation |
| `tss::committee` | 72 | Member/Committee/Receipt validation, cross-field checks (epoch match, signer_ids match), compute_hash |
| `tss::tests` (integration) | 19 | Cross-type roundtrips, hash determinism across all TSS types, encoding determinism, Send+Sync, Error trait |

Every encoding function is tested for:

- **Determinism**: encoding the same value twice produces identical bytes.
- **Roundtrip**: `decode(encode(x)) == x` for all valid inputs.
- **Hash stability**: the same input always produces the same SHA3-256 digest.
- **Error handling**: empty input, truncated input, and garbage bytes all return typed errors (never panic).

---

## Dependencies

| Crate | Purpose |
|-------|---------|
| `serde` + `serde_derive` | Derive-based serialization for all schema types |
| `bincode` | Deterministic binary encoding (little-endian, fixed-width) |
| `sha3` | SHA3-256 hashing for commitments and integrity checks |
| `serde_big_array` | Serde support for fixed-size arrays > 32 bytes (e.g., `[u8; 29]` namespace) |
| `serde_json` | JSON serialization (used in TSS wrapper type tests) |

---

## Usage Examples

### Encoding and hashing a DA event

```rust
use dsdn_proto::da_event::DAEvent;
use dsdn_proto::encoding::{encode_event, decode_event, compute_event_hash};

let event = DAEvent::ChunkDeclared {
    version: 1,
    timestamp_ms: 1704067200000,
    chunk_hash: "abc123".to_string(),
    size_bytes: 16_777_216,
    uploader_id: "node-42".to_string(),
    replication_factor: 3,
};

let bytes = encode_event(&event);
let hash = compute_event_hash(&event);

// Any node decoding the same bytes gets the identical event
let decoded = decode_event(&bytes).expect("valid event");
assert_eq!(decoded, event);

// And computes the identical hash
assert_eq!(compute_event_hash(&decoded), hash);
```

### Working with fallback events

```rust
use dsdn_proto::{
    FallbackEvent, FallbackActivated, FallbackType,
    FALLBACK_EVENT_SCHEMA_VERSION,
};
use dsdn_proto::encoding::{
    encode_fallback_event, decode_fallback_event,
    compute_fallback_event_hash, verify_fallback_event_hash,
};

let event = FallbackEvent::FallbackActivated {
    version: FALLBACK_EVENT_SCHEMA_VERSION,
};

let bytes = encode_fallback_event(&event);
let hash = compute_fallback_event_hash(&event);

assert!(verify_fallback_event_hash(&event, &hash));

let decoded = decode_fallback_event(&bytes).expect("valid fallback event");
assert_eq!(decoded, event);
```

### Tracking pending blobs during fallback

```rust
use dsdn_proto::pending_blob::{PendingBlob, MAX_RETRY_COUNT};
use dsdn_proto::encoding::compute_pending_blob_hash;

let blob = PendingBlob {
    data: vec![0xDE, 0xAD, 0xBE, 0xEF],
    original_sequence: 42,
    source_da: "validator_quorum".to_string(),
    received_at: 1704067200,
    retry_count: 0,
    commitment: None,
};

assert_eq!(blob.size_bytes(), 4);
assert!(!blob.is_expired()); // retry_count (0) <= MAX_RETRY_COUNT (3)

let hash = compute_pending_blob_hash(&blob);
// hash is deterministic — same blob always produces the same [u8; 32]
```

### Building a consistency report

```rust
use dsdn_proto::consistency_report::{
    ConsistencyReport, ConsistencyMismatch, MismatchType,
};

let report = ConsistencyReport {
    celestia_height: 10_000,
    fallback_height: 500,
    is_consistent: false,
    mismatches: vec![
        ConsistencyMismatch {
            sequence: 42,
            celestia_hash: None,
            fallback_hash: Some([0xAB; 32]),
            mismatch_type: MismatchType::Missing,
        },
    ],
    checked_at: 1704067200,
    check_duration_ms: 1500,
};

assert!(!report.is_consistent);
assert_eq!(report.mismatches.len(), 1);
```

### DKG round 1 — create, validate, encode, hash

```rust
use dsdn_proto::tss::{
    DKGRound1PackageProto,
    encode_dkg_round1, decode_dkg_round1, compute_dkg_round1_hash,
};

let package = DKGRound1PackageProto {
    session_id: vec![0x01; 32],
    participant_id: vec![0x02; 32],
    commitment: vec![0x03; 32],
    proof: vec![0x04; 64],
};

// Validate field sizes before sending
package.validate().expect("valid DKG Round 1 package");

// Encode → decode roundtrip
let bytes = encode_dkg_round1(&package);
let decoded = decode_dkg_round1(&bytes).expect("decode success");
assert_eq!(package, decoded);

// Deterministic hash for broadcast verification
let hash = compute_dkg_round1_hash(&package);
assert_eq!(compute_dkg_round1_hash(&decoded), hash);
```

### Threshold signing — request through aggregation

```rust
use dsdn_proto::tss::{
    SigningRequestProto, SigningCommitmentProto,
    PartialSignatureProto, AggregateSignatureProto,
    encode_aggregate_signature, compute_aggregate_signature_hash,
};

// 1. Client creates signing request
let request = SigningRequestProto {
    session_id: vec![0x01; 32],
    message: b"transfer 100 DSDN".to_vec(),
    message_hash: vec![0xAA; 32],
    required_signers: vec![vec![0x10; 32], vec![0x20; 32]],
    epoch: 5,
    timeout_secs: 30,
    request_timestamp: 1704067200,
};
request.validate().expect("valid signing request");

// 2. Each signer produces a commitment (hiding + binding nonces)
let commitment = SigningCommitmentProto {
    session_id: vec![0x01; 32],
    signer_id: vec![0x10; 32],
    hiding: vec![0xBB; 32],
    binding: vec![0xCC; 32],
    timestamp: 1704067201,
};
commitment.validate().expect("valid commitment");

// 3. Each signer produces a partial signature
let partial = PartialSignatureProto {
    session_id: vec![0x01; 32],
    signer_id: vec![0x10; 32],
    signature_share: vec![0xDD; 32],
    commitment: commitment.clone(),
};
partial.validate().expect("valid partial signature");

// 4. Coordinator aggregates into FROST signature
let aggregate = AggregateSignatureProto {
    signature: vec![0xFF; 64],  // 64-byte R ‖ s
    signer_ids: vec![vec![0x10; 32], vec![0x20; 32]],
    message_hash: vec![0xAA; 32],
    aggregated_at: 1704067202,
};
aggregate.validate().expect("valid aggregate signature");

let hash = compute_aggregate_signature_hash(&aggregate);
// hash is deterministic — used as the signing proof commitment
```

### Committee-signed receipt

```rust
use dsdn_proto::tss::{
    ReceiptDataProto, ThresholdReceiptProto, AggregateSignatureProto,
    encode_receipt, decode_receipt, compute_receipt_hash,
};

let receipt_data = ReceiptDataProto {
    workload_id: vec![0x01; 32],
    blob_hash: vec![0x02; 32],
    placement: vec![vec![0x03; 32], vec![0x04; 32]],
    timestamp: 1704067200,
    sequence: 1,
    epoch: 5,
};

// compute_hash() is the binding commitment the committee signs
let data_hash = receipt_data.compute_hash();

let receipt = ThresholdReceiptProto {
    receipt_data,
    signature: AggregateSignatureProto {
        signature: vec![0xAA; 64],
        signer_ids: vec![vec![0x10; 32], vec![0x20; 32]],
        message_hash: vec![0xBB; 32],
        aggregated_at: 1704067201,
    },
    signer_ids: vec![vec![0x10; 32], vec![0x20; 32]],
    epoch: 5,
    committee_hash: vec![0xCC; 32],
};
receipt.validate().expect("valid threshold receipt");

// Encode/decode roundtrip
let bytes = encode_receipt(&receipt);
let decoded = decode_receipt(&bytes).expect("decode success");
assert_eq!(compute_receipt_hash(&receipt), compute_receipt_hash(&decoded));
```

---

## License

Part of the DSDN project. See the repository root for license terms.