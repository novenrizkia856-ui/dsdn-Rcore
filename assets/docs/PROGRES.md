1 - 14.2b.2 = Finished
focus on stage which is being worked on


[Active_stage]
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