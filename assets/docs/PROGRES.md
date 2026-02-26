1 - 14.2b.2 = Finished
focus on stage which is being worked on


[Active_stage]
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