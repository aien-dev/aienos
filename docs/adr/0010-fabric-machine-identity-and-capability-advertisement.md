# ADR 0010: Fabric Machine Identity and Capability Advertisement

Status: Proposed.

Open for early discussion per
[issue #37](https://github.com/aien-dev/aienos/issues/37). Not yet accepted.
Nothing in this record is active before native networking
([M6](../MILESTONES.md)) and the preconditions below are met. No code is
mandated by this record.

Governing: [ARCHITECTURE.md section 2](../ARCHITECTURE.md) (Personal Fabric),
[BLUEPRINT.md section 25](../BLUEPRINT.md) (Phase 8 Personal Fabric),
[BLUEPRINT.md section 26](../BLUEPRINT.md) (state mobility),
[BLUEPRINT.md section 21](../BLUEPRINT.md) (Machine Capsule),
[MILESTONES.md Phase 8](../MILESTONES.md), [ADR 0004](0004-reversibility-definition-and-network-effect-boundary.md),
[ADR 0007](0007-continuous-existence-provisioning-once.md).

## Context

The architecture already fixes the endpoint: a given computer is Machine N,
not "the AIEN computer"; hardware and vendor details are capabilities, not
identities (ARCHITECTURE.md section 2). One logical AIEN spans several
machines, and the machines are resources of the operator's environment
(BLUEPRINT.md section 25). Phase 8 assigns this work to a future
`crates/aienos-fabric/` crate covering peer-to-peer capability discovery,
state synchronization, and RPC.

Issue #37 asks for early design discussion on the two questions that precede
everything else in the fabric:

1. Under what identity does a machine join the fabric.
2. What a joining machine advertises about itself, and how that advertisement
   is represented, authorized, bounded, and kept current.

Deciding these two points early keeps M6 networking work from accidentally
hardening brand-based identity, unsolicited broadcast behaviour, or an
advertisement format that bypasses AEGIS. This record captures the design
constraints so that early work can proceed in parallel with the M0 to M6
critical path without premature protocol commitment.

## Decision

### Identity: machines join under a Machine ID, never a brand

1. A machine joins the fabric under a `MachineId`: a stable, opaque,
   operator-provisioned identifier generated locally at provisioning time and
   bound to the operator's AIEN environment. Following the continuous-existence
   rule (ADR 0007), a `MachineId` is created once per physical machine at
   provisioning; boot, reboot, kernel restart, and model reload resume it and
   never mint a replacement.
2. Vendor, brand, model name, and marketing identifiers ("NVIDIA", "DGX
   Spark") are capability data, never identity. A replacement machine with the
   same brand is a different `MachineId`; the same machine with replaced parts
   keeps its `MachineId`. The DGX Spark is the reference machine, not AIEN's
   identity (BLUEPRINT.md section 24).
3. The machine's hardware description is a Machine Capsule (BLUEPRINT.md
   section 21): CPU, accelerator, memory, storage, network, display, audio,
   USB, Bluetooth, input, known drivers, and compatibility requirements.
   The capsule is a property of the machine record, not of the identity.
4. The `MachineId` is distinct from the `LogicalAgentId`. The agent identity
   exists above machines (Blueprint section 25); a machine never impersonates
   the agent, and agent migration between machines is an execution-state
   transition recorded with a continuity receipt, not a new agent.

### Advertisement: declared capability set

5. A joining machine advertises exactly the categories named in issue #37:
   - **CPU**: topology, architecture, efficiency classes, frequency
     envelopes, as discovered by native topology discovery (M2 already
     provides the baseline).
   - **Memory**: total and available capacity, unified-memory properties and
     block budgets per ADR 0005.
   - **Accelerators**: presence, class, and driver status (for example the
     GB10 GPU as a characterized capability, per issue #36 work; accelerator
     presence is capability data even before accelerator execution exists).
   - **Models**: model identities and versions currently loadable on this
     machine, behind the Model ABI; a model is a replaceable component, never
     an identity.
   - **Tools**: the capability surface the machine can execute, in the same
     vocabulary AEGIS uses for capability scope (`fs.write`, `code.build`,
     and similar names), so placement decisions and authorization decisions
     read the same data.
   - **Load**: current dynamic pressure (scheduler occupancy, memory
     pressure, thermal and power state where measurable), advertised as a
     separate, short-lived class of data from the static capability set.
6. Static capabilities and dynamic load are distinct records with distinct
   lifetimes. Static data changes only on provisioning, hardware change, or
   software update and is signed once per change; load data is unsigned
   telemetry-grade information refreshed periodically and never used for
   authorization decisions.
7. Advertisement is pull-or-respond within the operator's own fabric, not
   open broadcast. A machine answers capability queries from machines it has
   been provisioned to trust; it does not announce itself to the local
   network at large, and it does not respond to unprovisioned requesters.
8. Every advertisement exchange is an outbound network effect and therefore
   crosses the AEGIS boundary (ADR 0004): even read-only capability queries
   are `EffectIntent`s evaluated against capability grants. Fabric
   participation never bypasses AEGIS under the label of discovery or
   research.

### Representation and scope

9. The capability advertisement derives from the Machine Capsule and reuses
   the machine's existing discovered evidence (CPU topology, memory map,
   identity reports) rather than introducing a parallel inventory path.
10. Advertisements are bounded in size, versioned in schema, and validated on
    receipt. A received advertisement grants the sender nothing; it is input
    to the receiving machine's own placement and scheduling decisions.
11. Partition sovereignty (MILESTONES.md Phase 8) applies to identity:
    disconnection never invalidates a `MachineId` or an advertised
    capability record; a disconnected machine falls back to autonomous local
    operation with its last committed records.

### Activation boundary (post-M6)

12. This design activates only after M6 minimal networking provides the
    secure control transport. Until then, no crate implements this record;
    host-side prototypes may model the data structures for discussion, but
    nothing ships in the trusted base.

## Preconditions

Before any implementation of this record may merge:

1. M6 minimal networking (DHCP/static IP, ARP/NDP, IP, UDP/TCP, secure
   control transport) is complete and evidenced.
2. The `MachineId` provisioning flow is defined with the same
   provisioning-once discipline as `LogicalAgentId` (ADR 0007), including
   Recovery Core behaviour when machine identity state cannot be verified.
3. The advertisement wire format is specified with its schema version,
   size bounds, signature scheme, and validation rules, and reviewed as an
   irreversible data format per CONTRIBUTING.md.
4. Operator approval per the governance rule in this directory, since this
   record touches persistent identity and a security boundary.

## Invariants

1. **Identity above machines**: the `LogicalAgentId` never depends on any
   `MachineId`; machines are replaceable substrate.
2. **Brand is not identity**: no protocol field, log line, or proof receipt
   may use vendor or product names where a `MachineId` belongs.
3. **AEGIS boundary**: all fabric traffic, including read-only capability
   advertisement, is an external effect under AEGIS evaluation (ADR 0004).
4. **Capsule-derived advertisement**: the advertised static capability set is
   derived from the Machine Capsule and native discovery evidence, not from
   hand-maintained configuration.
5. **Partition sovereignty**: loss of fabric connectivity never blocks local
   core operation or corrupts identity state.
6. **Secrets invariant**: NO PLAINTEXT SECRETS IN REPOSITORY OR BUILD
   ARTIFACTS.
7. **Unslop standard**: zero em dashes, zero en dashes, and direct technical
   documentation.

## Consequences

- M6 networking work can proceed knowing the fabric will use
  operator-scoped pull-or-respond discovery, avoiding accidental broadcast
  protocol commitments.
- Issue #36 (GB10 characterization) output feeds the accelerator entry of
  the capability advertisement when the fabric activates.
- The future `crates/aienos-fabric/` crate starts from a defined identity
  model and capability vocabulary rather than inventing them during Phase 8.
- State mobility (Blueprint section 26) and the heterogeneous compute
  scheduler (MILESTONES.md Phase 8) consume the capability advertisement as
  their placement input.
- This record remains a design record until the operator accepts it; early
  discussion continues on issue #37.
