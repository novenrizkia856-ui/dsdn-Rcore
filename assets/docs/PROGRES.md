1 - 14.2b.2 = Finished
14B = Execution

focus on stage which is being worked on

## Tahap 14C.A --- Execution Commitment & Receipt v1 Foundation

**Tujuan:** Membangun struct dasar ExecutionCommitment dan ReceiptV1, beserta serialization, hashing, dan unit test.

**Prinsip:**
- Semua struct harus deterministic serialization (canonical encoding).
- Tidak ada adaptive logic.
- Fokus pada data layer, belum ada on-chain processing.

### Execution Commitment Struct
```rust
struct ExecutionCommitment {
    workload_id: WorkloadId,
    input_hash: Hash,
    output_hash: Hash,
    state_root_before: Hash,
    state_root_after: Hash,
    execution_trace_merkle_root: Hash,  // preparation untuk fraud proof
}
```

- Implementasi `ExecutionCommitment::new(...)`, `hash()`, `verify_structure()`.
- Canonical serialization (borsh/bincode, pilih satu, konsisten).
- `execution_trace_merkle_root` boleh dummy/zeroed untuk tahap ini, tapi field wajib ada.

### Receipt v1 Struct
```rust
struct ReceiptV1 {
    workload_id: WorkloadId,
    node_id: NodeId,
    usage_proof_hash: Hash,
    execution_commitment: ExecutionCommitment,
    coordinator_threshold_signature: FrostSignature,
    node_signature: Ed25519Signature,
    submitter_address: Address,
}
```

- Implementasi `ReceiptV1::new(...)`, `hash()`, `verify_signatures()`.
- Signature verification: node_signature (Ed25519) + coordinator FROST threshold signature.
- Receipt hashing harus deterministic dan reproducible.

### Deliverables

1. `ExecutionCommitment` struct + impl di `common` atau `proto`.
2. `ReceiptV1` struct + impl di `common` atau `proto`.
3. Serialization round-trip test (serialize → deserialize → equal).
4. Signature creation + verification helpers.
5. Unit test: valid receipt, invalid signature rejected, tampered commitment detected.

### Crates Terlibat

`common`, `proto`, `tss` (untuk FROST signature types)

### Kriteria Selesai

- `ExecutionCommitment` dan `ReceiptV1` compile, serialize, deserialize deterministic.
- Signature verify works untuk valid case, reject untuk invalid case.
- Semua unit test pass.
- Tidak ada logic on-chain di tahap ini.
