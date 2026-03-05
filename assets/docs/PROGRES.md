1 - 14.2b.2 = Finished
focus on stage which is being worked on


[Active_stage]
## Tahap 15 — Logging & Audit Infrastructure (WORM + DA Mirror Core)

**Fokus:** Membangun fondasi logging infrastructure — WORM writer, DA mirror sync, event schema, dan trait/hook interface. Belum integrasi ke service crates.

**Perubahan dari blueprint:** Audit log penting harus disimpan lokal sebagai WORM dan dipost ke Celestia DA untuk immutability.

**Deliverables:**

1. **`proto`** — Definisi `LogEventType` enum dengan semua variant:
   - Slashing events
   - Stake updates
   - Anti-self-dealing violation logs
   - User-controlled delete
   - DA-sync sequence number
   - Governance proposal + delay window
   - Coordinator committee rotation events (`// Producer: Tahap 20`)
   - DA fallback activation/deactivation events (`// Producer: Tahap 15.1`)
   - Compute challenge events (`// Producer: Tahap 18.1`)

   Setiap variant memiliki schema struct lengkap dengan field definitions.

2. **`common`** — Core logging traits dan utilities:
   - `AuditLogWriter` trait: accept event → persist ke WORM + DA mirror
   - `AuditLogHook` trait: interface yang bisa dipanggil producer di tahap mendatang
   - `WormLogStorage` trait: append-only local persistence abstraction
   - `DaMirrorSync`: DA layer sync logic (sequence numbering, batch publish)
   - Deterministic encoding (canonical JSON / protobuf)
   - Timestamp consistency (Unix epoch)
   - Error types untuk log failures (no silent failure)

3. **`storage`** — WORM persistence layer:
   - `WormFileStorage` implementing `WormLogStorage`
   - Append-only file backend (no overwrite, no delete)
   - Rotation / compaction policy (configurable max size)
   - Integrity verification (hash chain per entry)
   - Recovery from partial writes

> **Catatan Implementasi (FIX #5):** Untuk setiap log type yang producer-nya belum exist:
> 1. Definisikan `LogEventType` enum variant dan schema struct di `proto`.
> 2. Implementasi log writer di `common` yang bisa menerima event dan persist ke WORM + DA.
> 3. Buat trait/interface hook di `common` yang bisa dipanggil oleh producer di tahap mendatang.
> 4. Tandai dengan `// Producer: Tahap X` di code.
> 5. Unit test: pastikan hook callable dan log writer berfungsi (dengan synthetic/mock events).

**Selesai jika:**
- Semua `LogEventType` variants terdefinisi di `proto` dengan schema struct.
- `AuditLogWriter` + `AuditLogHook` traits terimplementasi di `common`.
- WORM file storage berfungsi (append-only, integrity-verified).
- DA mirror sync berfungsi (dengan mock DA publisher).
- Unit tests: semua schema serializable, semua hooks callable, WORM append-only verified, DA sync 100% match.

**Crates yang diubah:** `proto`, `common`, `storage`.