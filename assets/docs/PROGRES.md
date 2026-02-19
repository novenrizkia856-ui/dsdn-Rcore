1 - 14.2b.2 = Finished
focus on stage which is being worked on


[Active_stage]
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