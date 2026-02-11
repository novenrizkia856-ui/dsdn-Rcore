# dsdn-validator

Validator library untuk **DSDN** (Decentralized Storage and Data Network). Menyediakan manifest validation, QuorumDA (secondary Data Availability layer), coordinator selection, dan **service node gating** — sistem verifikasi admission berbasis stake, identitas, TLS, dan slashing cooldown.

## Arsitektur Crate

```
crates/validator/
├── src/
│   ├── lib.rss                          # Entry point + public exports
│   │
│   ├── quorum_da.rs                       # QuorumDA System (14A.1A.21–30)
│   │
│   ├── coordinator_selection/           # Coordinator Selection (14A.2B.2)
│   │   └── mod.rs                       # ValidatorCandidate, CommitteeSelection, VRF
│   │
│   └── gating/                          # Service Node Gating (14B.21–30)
│       ├── mod.rs                       # Module re-exports
│       ├── stake_verifier.rs           # 14B.21 — Stake requirement check
│       ├── identity_verifier.rs        # 14B.22 — Ed25519 proof + operator binding
│       ├── tls_verifier.rs             # 14B.23 — TLS cert validity + fingerprint
│       ├── cooldown_verifier.rs        # 14B.24 — Slashing cooldown enforcement
│       ├── class_verifier.rs           # 14B.25 — NodeClass claim validation
│       ├── engine.rs                   # 14B.26 — GatingEngine orchestrator
│       ├── admission.rs                # 14B.27 — AdmissionPolicy (time-based rules)
│       ├── report.rs                   # 14B.28 — ReportGenerator (table + JSON)
│       └── tests.rs                    # 14B.30 — Integration tests (56 tests)
└── Cargo.toml
```

## Module Overview

### Manifest Validation

Validasi deklaratif untuk application manifest:

- Syntactic validation (SHA-256 hex hash format)
- Banned-hash detection
- Signature presence/format check
- Basic SBOM presence check

### QuorumDA System (14A.1A)

Secondary Data Availability layer dalam DSDN fallback hierarchy. QuorumDA aktif hanya ketika Celestia (primary DA) tidak tersedia.

```
Priority 1 (Primary)   → Celestia      — DAStatus::Healthy
Priority 2 (Secondary) → QuorumDA      — DAStatus::Degraded
Priority 3 (Emergency) → Foundation DA — DAStatus::Emergency
```

QuorumDA mengextend `DALayer` trait dari `dsdn_common` dengan quorum-based signature collection dan verification.

### Coordinator Selection (14A.2B.2)

Deterministic committee selection menggunakan ChaCha20 PRNG dan SHA3-256 epoch seed derivation. Mendukung weighted selection berdasarkan stake dan optional gating filter.

### Service Node Gating (14B)

Sistem verifikasi **stateless** dan **deterministic** untuk admission control service node. Setiap verifier memproduksi `CheckResult` atau `GatingError` tanpa mengakses chain state, system clock, atau I/O.

## Gating System

### Design Properties

| Property | Guarantee |
|----------|-----------|
| **Stateless** | Tidak ada mutable state antar evaluasi |
| **Deterministic** | Input sama → output identik (bitwise-equal) |
| **Pure** | Tidak ada system clock, randomness, atau side effect |
| **Safe** | Tidak ada `unwrap()`, `expect()`, panic, atau silent failure |
| **Send + Sync** | Semua verifier aman untuk concurrent access |

### Verifier Catalog

| Verifier | Module | Check | Error Variant |
|----------|--------|-------|---------------|
| `StakeVerifier` | `stake_verifier` | stake ≥ min untuk NodeClass | `ZeroStake`, `Ok(passed=false)` |
| `IdentityVerifier` | `identity_verifier` | Ed25519 proof + operator binding | `IdentityVerificationFailed`, `IdentityMismatch` |
| `TLSVerifier` | `tls_verifier` | Cert time + fingerprint + subject CN | `TLSInvalid(Expired\|NotYetValid\|FingerprintMismatch\|EmptySubject)` |
| `CooldownVerifier` | `cooldown_verifier` | Slashing cooldown expired? | `SlashingCooldownActive` |
| `ClassVerifier` | `class_verifier` | Claimed class affordable? | `InvalidNodeClass` |

### GatingEngine — Evaluation Order

`GatingEngine::evaluate()` menjalankan semua check dalam urutan **consensus-critical** yang fixed. Engine **tidak pernah short-circuit** — semua error dikumpulkan.

```
CHECK 1: StakeVerifier      → ZeroStake (hard error) atau Ok(passed=true/false)
CHECK 2: ClassVerifier       → InvalidNodeClass (hard error) atau Ok
CHECK 3: IdentityVerifier    → skip jika policy.require_identity_proof == false
CHECK 4: TLSVerifier         → skip jika policy.require_tls == false
CHECK 5: CooldownVerifier    → SlashingCooldownActive atau pass
```

**Keputusan akhir:**
- 0 errors → `GatingDecision::Approved`
- ≥1 errors → `GatingDecision::Rejected(Vec<GatingError>)` (urutan sesuai evaluation order)

### Perbedaan StakeVerifier vs ClassVerifier

Kedua verifier bekerja sama tetapi berbeda di semantik error:

| Kondisi | StakeVerifier | ClassVerifier |
|---------|---------------|---------------|
| stake = 0 | `Err(ZeroStake)` | `Err(InvalidNodeClass)` |
| 0 < stake < min | `Ok(passed=false)` | `Err(InvalidNodeClass)` |
| stake ≥ min | `Ok(passed=true)` | `Ok(passed=true)` |

Engine hanya mengumpulkan `Err(...)` — artinya `Ok(passed=false)` dari StakeVerifier **tidak** menjadi error di engine, tetapi `Err(InvalidNodeClass)` dari ClassVerifier **tetap** tertangkap.

### AdmissionPolicy

Wraps `GatingPolicy` dengan time-based rules:

- `should_auto_reject_pending(registered_at, current)` — strict `>` (elapsed == max → NOT rejected)
- `should_escalate_quarantine(quarantined_at, current)` — strict `>` (elapsed == max → NOT escalated)
- Clock skew safe: `current < reference` → returns `false`

**Presets:**

| Preset | Security | Pending Timeout | Quarantine Timeout |
|--------|----------|-----------------|---------------------|
| `default()` | Full (all checks) | 1 hour | 24 hours |
| `permissive()` | None (testing only) | u64::MAX | u64::MAX |

### ReportGenerator

Zero-sized struct yang menghasilkan `GatingReport` audit trail:

- `generate(identity, decision, checks, timestamp)` → `GatingReport`
- `to_table(report)` → human-readable fixed-width table
- `to_json(report)` → machine-readable JSON (serde roundtrip safe)

## Dependencies

### From `dsdn_common::gating`

| Type | Role |
|------|------|
| `NodeIdentity` | node_id (Ed25519 pubkey), operator_address, tls_cert_fingerprint |
| `NodeClass` | `Storage` (min 5000 NUSA) / `Compute` (min 500 NUSA) |
| `StakeRequirement` | Per-class minimum stakes (18 decimals on-chain) |
| `GatingPolicy` | Combined config: stake, cooldown, TLS, identity, scheduling |
| `GatingDecision` | `Approved` / `Rejected(Vec<GatingError>)` |
| `GatingError` | 10 structured error variants |
| `CheckResult` | `{ check_name, passed, detail }` |
| `GatingReport` | Full audit report with identity, decision, checks, timestamp |
| `CooldownPeriod` | start_timestamp, duration_secs, reason |
| `CooldownConfig` | default (24h), severe (7d) durations |
| `TLSCertInfo` | fingerprint, subject_cn, not_before/after, issuer |
| `TLSValidationError` | Expired, NotYetValid, FingerprintMismatch, EmptySubject, MissingCert |
| `IdentityChallenge` | nonce (32 bytes), timestamp, challenger |
| `IdentityProof` | challenge + signature (64 bytes) + node_identity |

### From `dsdn_chain::gating`

| Type | Role |
|------|------|
| `ServiceNodeRecord` | On-chain record (used by `CooldownVerifier::verify_from_record`) |

### External

| Crate | Usage |
|-------|-------|
| `ed25519-dalek` | Identity proof verification (verify_strict) |
| `sha2` | TLS fingerprint computation (SHA-256) |
| `hex` | Fingerprint/identity display in detail messages |
| `serde` / `serde_json` | AdmissionPolicy + GatingReport serialization |
| `rand` / `rand_chacha` | Coordinator selection (ChaCha20 PRNG) |
| `sha3` | Epoch seed derivation |

## Usage

### Basic Gating Evaluation

```rust
use dsdn_common::gating::{GatingPolicy, NodeClass, StakeRequirement};
use dsdn_validator::gating::{GatingEngine, StakeVerifier};

// Create engine with production policy
let policy = GatingPolicy::default();
let engine = GatingEngine::new(policy, current_timestamp);

// Evaluate a node
let decision = engine.evaluate(
    &node_identity,
    &NodeClass::Storage,
    actual_stake,          // u128
    cooldown.as_ref(),     // Option<&CooldownPeriod>
    tls_info.as_ref(),     // Option<&TLSCertInfo>
    identity_proof.as_ref(), // Option<&IdentityProof>
);

if decision.is_approved() {
    // Node admitted
} else {
    for error in decision.errors() {
        eprintln!("Gating error: {}", error);
    }
}
```

### Generate Audit Report

```rust
use dsdn_validator::gating::report::ReportGenerator;

let report = ReportGenerator::generate(&identity, decision, checks, timestamp);

// Human-readable table (CLI/dashboard)
println!("{}", ReportGenerator::to_table(&report));

// Machine-readable JSON (logging/API)
let json = ReportGenerator::to_json(&report);
```

### Admission Policy with Time-Based Rules

```rust
use dsdn_validator::gating::admission::AdmissionPolicy;

let admission = AdmissionPolicy::default();

// Check if pending node should be auto-rejected
if admission.should_auto_reject_pending(registered_at, current_timestamp) {
    // Reject: node exceeded 1-hour pending timeout
}

// Check if quarantined node should be escalated (banned)
if admission.should_escalate_quarantine(quarantined_at, current_timestamp) {
    // Escalate: node exceeded 24-hour quarantine timeout
}
```

### Testing with Permissive Policy

```rust
// Disables all security checks — NEVER use in production
let policy = GatingPolicy::permissive();
let engine = GatingEngine::new(policy, timestamp);

// Note: even permissive rejects stake=0 (ZeroStake is unconditional)
// Use stake=1 for minimal pass with permissive policy
```

## Test Coverage

| Category | Tests | Description |
|----------|-------|-------------|
| Full Pipeline | 3 | Engine → Report → JSON roundtrip |
| Cross-Verifier | 4 | StakeVerifier ↔ ClassVerifier boundary agreement |
| Error Order | 3 | Consensus-critical error ordering enforcement |
| Skip Logic | 5 | Policy-driven identity/TLS check toggling |
| Admission + Engine | 7 | Time-based timeout + gating integration |
| Report Fidelity | 4 | Check order, JSON fields, table format |
| Edge Cases | 10 | Permissive, u128::MAX, cooldown boundaries |
| Determinism | 4 | Repeated evaluations → identical results |
| Verifier X-checks | 4 | TLS order, cooldown boundary, fingerprint |
| Send + Sync | 1 | All 8 types thread-safe |
| Policy Validation | 4 | Hierarchy, zero-stake contradictions |
| Multi-Error | 3 | Combined TLS + cooldown, overclaim |
| Report Summary | 2 | `summary()` format verification |
| Boundary Sweep | 2 | Storage + Compute stake sweep |
| **Total** | **56** | **Per-verifier unit tests + integration** |

Run tests:

```bash
cargo test -p dsdn-validator -- gating
```

## Roadmap

Gating system ini akan digunakan oleh **Coordinator crate** (14B.31–40) untuk enforce gatekeeping saat node join dan scheduling:

- `GateKeeper` — runtime gating enforcement
- `NodeAdmissionFilter` — join request filtering
- `PeriodicRecheck` — re-evaluation of active nodes
- `QuarantineManager` — automated quarantine/ban escalation

## License

Proprietary — DSDN Project