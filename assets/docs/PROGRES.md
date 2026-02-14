1 - 14.2b.2 = Finished
14B = Execution

focus on stage which is being worked on

## Stage 14B --- Stake and Identity Gating (Security-First, No Economy)

**Objective:** Lock down who is allowed to become a node before the economic system is live. This stage separates security bugs from economic bugs.

**Key Principles:**

- Nodes must not be active without stake and identity verification.
- Rewards do not exist yet.
- Receipts do not exist yet.

### New Mechanisms

#### 1. Node Identity

Every node must have: a valid TLS certificate, an Ed25519 `node_id`, and an `operator_address` (wallet).

#### 2. Required Chain API

Exposed on Chain Nusantara: `get_stake(address)`, `get_node_class(address)`, `get_slashing_status(address)`.

#### 3. Coordinator Gatekeeping

Coordinator rejects a node if: stake < 500 / 5000, slashing cooldown is active, TLS is invalid, or `node_id` does not match the operator.

#### 4. Node Lifecycle

Node statuses: `Pending`, `Active`, `Quarantined`, `Banned`. A node will not be scheduled unless its status = `Active`.

### Required Validations

- Node without stake --- rejected.
- Node with insufficient stake --- quarantined.
- Node with prior slashing --- cooldown enforced.
- Identity spoofing --- join fails.

### Completion Criteria

- Only valid nodes are active.
- Scheduler cannot select illegal nodes.
- System is secure without active rewards.

**Crates involved:** `coordinator`, `node`, `validator`, `chain`, `agent`, `common`.

> The stake mechanism in this stage functions solely as a security gate, not as an economic signal, ROI indicator, or public participation incentive. Completion of this stage must not be interpreted as activation of the network economy or as an indicator of ROI viability for operators.