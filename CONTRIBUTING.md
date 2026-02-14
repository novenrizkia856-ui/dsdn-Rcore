# Contributing to DSDN

DSDN adalah proyek infrastruktur dengan arsitektur deterministik dan model verifiable-by-design.  
Kontribusi harus mengikuti arah pengembangan aktif dan tidak boleh menyimpang dari tahap yang sedang berjalan.

---

## Development Philosophy

DSDN dibangun secara bertahap dan berurutan.

- Tidak boleh melompat ke tahap berikutnya.
- Tidak boleh mengerjakan fitur masa depan.
- Tidak boleh eksperimen di luar tahap aktif.
- Semua kontribusi harus relevan dengan tahap pengembangan yang sedang berjalan.

Status tahap aktif dapat dilihat di file:
`/assets/docs/checklist_roadmap`

Dan roadmap tahap ada di:
`/assets/docs/roadmap.md`

Setiap Issue dan Pull Request harus menyebutkan stage aktif.

Contoh:

[Stage Active] Implement stake verification in coordinator


Pull Request harus mencantumkan:

Stage: Active
Closes #issue_number


---

## Approval & Review Policy

Semua Pull Request memerlukan:

- Minimal 1 maintainer approval sebelum merge.
- Review eksplisit untuk perubahan di modul kritikal.

Modul kritikal:

- `coordinator/`
- `chain/`
- `node/`
- `common/`

Perubahan pada modul tersebut akan diperiksa lebih ketat,
terutama terkait determinisme, keamanan, dan integritas state.

---

## Testing Requirements (Mandatory)

Semua Pull Request wajib menyertakan:

- Unit test yang relevan.
- Test harus lulus tanpa flaky behavior.
- Logic deterministik harus dapat direplay.

PR tanpa unit test akan ditolak.

Jika perubahan menyentuh:
- state reconstruction
- scheduling
- stake validation
- consensus logic

Maka test harus mencakup edge-case dan negative-case.

---

## AI-Assisted Contributions Policy

DSDN memperbolehkan penggunaan AI sebagai alat bantu coding.

Aturan:

1. Contributor tetap bertanggung jawab penuh atas kode yang dikirim.
2. AI boleh digunakan dalam bentuk apa pun.
3. Kode hasil AI harus:
   - Dipahami sepenuhnya oleh contributor.
   - Diaudit sebelum dikirim.
   - Dijelaskan secara ringkas di deskripsi PR.

Tambahkan label pada PR:

[AI-Assisted]


AI tidak boleh digunakan untuk:

- Mengubah logic deterministik tanpa audit.
- Mengganti primitive kriptografi.
- Menambahkan dependency eksternal tanpa review.

AI adalah tool.  
Keputusan akhir tetap pada manusia.

---

## Code Discipline

- Semua crate wajib dikompilasi menggunakan `cargo rustsp`.
- Modul dengan logic kritikal wajib menggunakan RustS+.
- Gunakan Rust pada bagian non-critical atau utility.

Format dan linting:

cargo rustsp build
cargo clippy
cargo fmt


PR yang gagal build akan ditolak.

---

## Pull Request Size

Maksimal 1000 LOC per PR.

Jika lebih besar:
- Pecah menjadi beberapa PR.
- Pastikan tiap PR tetap koheren dan bisa direview.

Tujuan: menjaga kualitas review dan menghindari perubahan besar tanpa audit memadai.

---

## Determinism Rule

DSDN mengandalkan deterministic replay.

Dilarang:

- Menggunakan randomness tanpa seed deterministik.
- Menggunakan system time langsung untuk logic konsensus.
- Menggunakan state lokal sebagai sumber kebenaran.

Semua state harus dapat direkonstruksi dari log yang tersedia.

---

## Dependencies

Dependency baru:

- Harus dijelaskan alasan teknisnya.
- Harus melalui review maintainer.
- Tidak boleh memperkenalkan non-deterministic behavior.

---

## Security Expectations

Kontributor harus mempertimbangkan:

- Anti-self-dealing
- Replay attack
- Signature verification
- State consistency
- Failure recovery

Jika perubahan menyentuh area tersebut, jelaskan implikasi keamanan dalam PR.

---

## Communication

Gunakan Issue sebelum membuat PR besar.

Diskusikan terlebih dahulu jika:

- Mengubah arsitektur.
- Mengubah interface publik.
- Mengubah logic kriptografi.
- Mengubah mekanisme state.

---

## Final Responsibility

Setiap kontributor bertanggung jawab penuh atas kode yang dikirim,
termasuk kode yang dihasilkan oleh AI.

DSDN adalah proyek jangka panjang.
Stabilitas dan determinisme lebih penting daripada kecepatan.