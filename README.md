<p align="center">
  <img src="assets/DSDN_logo.png" alt="DSDN Logo" width="220">
</p>

# DSDN — Distributed Storage & Data Network

**DSDN** is a **semi-decentralized distributed data and compute system**
designed to be **verifiable-by-design**, rather than relying on trust in a
single entity.

DSDN combines:
- data availability logging,
- cross-zone replication,
- isolated compute execution,
- and technically constrained governance & compliance.

This repository contains the **core DSDN implementation**, currently under
active development.

---

## Project Status

**Experimental / Work in Progress**  
Not production-ready. Architecture, APIs, and the state model **are subject to change**.

---

## Problem Statement

Modern internet infrastructure is heavily dependent on:
- centralized data centers,
- trusted operators,
- and single administrative control.

This creates:
- single points of failure,
- privacy risks,
- and concentration of power.

DSDN aims to move **data and compute** to a distributed node network,
without introducing new actors that must be trusted.

---

## Core Design Principles

- **Verifiable-by-design**  
  No coordinator, validator, or foundation serves as a single source of truth.

- **Deterministic state reconstruction**  
  Network state is rebuilt deterministically from Data Availability logs,
  not stored as authoritative state.

- **Minimal trust assumptions**  
  Nodes, validators, and coordinators are assumed untrusted by default.

- **Auditability & transparency**  
  All system decisions can be replayed and audited.

---

## High-Level Architecture

DSDN consists of three main planes:

### 1. Control Plane (Metadata)
- Metadata is posted as blobs to the **Data Availability layer**.
- Each node reconstructs local state through deterministic log replay.
- There is no single authoritative state.

### 2. Data & Compute Plane
- Data is stored as hash-addressed chunks.
- Replication target: **3 replicas across different zones**.
- Program execution runs in sandboxed environments:
  - WASM/WASI
  - microVM (e.g., Firecracker)

### 3. Governance & Compliance Plane
- Operated by validators with verified identities.
- Validators **do not have access to encrypted data**.
- Actions are limited to removing public pointers/endpoints, not physical data.

---

## Trust Model

- **Node**: untrusted → verified through replication & quorum  
- **Coordinator**: stateless → decisions are reconstructable  
- **Validator**: untrusted for privacy → does not hold decryption keys  
- **Foundation**: authority is limited and recorded on-chain  

Failure of any single component cannot alter the truth of network state.

*If you want a step-by-step guide on becoming a node operator,*
please see [DSDN_NODE_OPERATOR_GUIDE](assets/docs/DSDN_NODE_OPERATOR_GUIDE.md)

---

## Documentation

Full design and technical rationale are available in the DSDN whitepaper  
(see the `assets/docs/` folder).

Development roadmap from initial stages through large-scale production:
see [Roadmap](assets/docs/roadmap.md)

---

## CLI Usage

DSDN consists of several main components that can be run via CLI:

- `chain` → Nusantara Blockchain
- `node` → Storage & Compute node
- `storage` → Storage engine & chunk handling

Usage details are available at:

- [Chain CLI Guide](crates/chain/README.md)
- [Node CLI Guide](crates/node/README.md)
- [Storage Guide](crates/storage/README.md)

---

## Programming Languages

DSDN combines Rust and RustS+. Both Rust and RustS+ are intended to be the
primary languages of DSDN. RustS+ is a language with a Rust backend featuring
additional rules and different syntax, used in various places to make DSDN
more secure in terms of logic and bugs.

DSDN must be compiled using `cargo rustsp`.

[RustS+ Language](https://github.com/novenrizkia856-ui/rustsp-Rlang)

---

## License

MIT License.