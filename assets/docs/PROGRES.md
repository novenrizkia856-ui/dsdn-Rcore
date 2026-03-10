1 - 14.2b.2 = Finished
focus on stage which is being worked on


[Active_stage]
## Tahap 15.1 — Logging Integration (Service Hook Wiring + DA Fallback Events)

**Fokus:** Mengintegrasikan logging infrastructure dari Tahap 15 ke semua service crates. Memasang hooks, meng-emit real events, dan memastikan log–DA sync mirror 100% match end-to-end.

**Prerequisite:** Tahap 15 selesai (traits, schemas, WORM storage, DA mirror tersedia).

**Deliverables per crate:**

1. **`chain`** — Emit events:
   - Slashing events (saat slashing terjadi di DPoS consensus)
   - Stake update events (delegate, undelegate, redelegate)
   - Governance proposal + delay window events
   - Treasury burn events

2. **`validator`** — Emit events:
   - Anti-self-dealing violation logs
   - Validator reward claim events
   - Validator set change events

3. **`node`** — Emit events:
   - Compute challenge events (`// Producer aktif setelah Tahap 18.1, log schema + hook dipasang sekarang`)
   - Workload completion events
   - Node registration/deregistration

4. **`coordinator`** — Emit events:
   - Committee rotation events (`// Producer aktif setelah Tahap 20, hook dipasang sekarang`)
   - DA fallback activation/deactivation events (**producer aktif di tahap ini**)
   - Receipt generation events
   - Workload dispatch events

5. **`agent`** — Emit events:
   - Economic flow events (forward dari agent subsystem ke audit log)
   - Retry/failure events dari economic lifecycle

6. **`ingress`** — Emit events:
   - User-controlled delete events
   - DA-sync sequence number updates
   - Claim submission/acceptance/rejection audit trail (bridge dari `ReceiptEventLogger` 14C.C.28 ke WORM + DA mirror)

**Integration requirements:**

- Setiap service crate harus:
  - Inject `Arc<dyn AuditLogWriter>` via constructor/state
  - Call appropriate hook pada setiap event occurrence
  - Handle log failure gracefully (warn, don't crash)
  - Include structured context (crate name, event source, correlation ID)

- DA fallback events:
  - `coordinator` adalah **producer aktif** untuk DA fallback activation/deactivation
  - Events harus di-emit saat fallback state berubah (primary → secondary → emergency dan sebaliknya)
  - Harus include: timestamp, previous DA source, new DA source, reason

- End-to-end verification:
  - Integration test: emit event dari service → verify di WORM log → verify di DA mirror
  - Log–DA sync harus 100% match (no missing events)

**Selesai jika:**
- Semua 6 service crates terintegrasi dengan audit logging.
- DA fallback events aktif di-emit oleh `coordinator`.
- Hook untuk future producers (committee rotation Tahap 20, compute challenge Tahap 18.1) terpasang dan tested dengan mock events.
- Log–DA sync mirror 100% match (integration test verified).
- Semua event types yang producer-nya sudah aktif menghasilkan real events.

**Crates yang diubah:** `coordinator`, `chain`, `node`, `validator`, `agent`, `ingress`.

> Audit log pada fase ini belum bersifat compliance-grade untuk publik, dan hanya digunakan untuk internal verification dan forensik.