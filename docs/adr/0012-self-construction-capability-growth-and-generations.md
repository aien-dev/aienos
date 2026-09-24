# ADR 0012: Self-Construction, Capability Growth, and Reversible System Generations

Status: Accepted by the operator, 2026-09-24.
Governing: [ADR 0002](0002-incumbent-os-as-migration-environment.md), [ADR 0006](0006-deterministic-recovery-core-and-offline-operator-authority.md), [ADR 0007](0007-continuous-existence-provisioning-once.md), [ADR 0009](0009-el2-bootstrap-to-el1h-kernel-transition.md).
Roadmap: inserts SEED-0A before M3 and SEED-0B after the M3 isolation work ([`ROADMAP.md`](../../ROADMAP.md)).

## Context

The roadmap builds AIENOS the conventional way: a general-purpose kernel,
then storage, identity, networking, inference, and the agent. Two things
changed that.

1. **The engineer is now an AI.** Kernel and driver work on this repository is
   increasingly proposed by AI agents. On 2026-09-24 an agent produced a
   1,234-line USB keyboard driver (#58) against a ~600-line limit, and another
   agent wrote an unobserved root cause into an evidence file (#56). The
   deterministic gates (`scripts/verify_all.sh`, the repository rules) caught
   both. The pattern is: the engineer proposes, a separate deterministic
   mechanism decides.
2. **Continuity is already settled.** ADR 0007 makes AIEN provisioned once;
   power-on is reconstruction, not creation. What remains open is how the
   *machine around* AIEN comes to exist and change over time.

The operator settled this through three design-interview rounds on
2026-09-24. This ADR records the result.

## Decision

AIEN is not distributed as a finished, universal, general-purpose operating
system. The trusted base supplies mechanisms; each machine grows the
capabilities it and its owner need, and every accepted change is a numbered,
reversible Generation admitted by deterministic gates.

### The three pieces

```text
AIEN SEED        Continuity and recovery root. Tiny, boring, deterministic.
                 Establishes owner trust, identifies the machine, locates and
                 verifies the accepted Generation, recovers, rolls back.
                 Contains no model and needs none.

AIEN FORGE       The self-construction machinery: the engineering agent,
                 reproducible builds, Worlds, tests, proofs, benchmarks.

AIEN GENERATION  The current accepted expression of one machine:
                 capabilities + policies + interface + state.
```

The Seed and Forge machinery may have versioned releases. A person's complete
AIEN is never a universal release; each machine evolves through its own
Generations.

### Rules

1. **Prove locally, design generally.** Machine 1 (the Spark) is the proving
   ground. Nothing fundamental is Spark-specific unless it sits behind a
   machine/BSP boundary.
2. **Survival kit, then growth.** Every AIEN has what it needs to exist and
   recover: console/display, input, storage, networking, time, recovery,
   identity, and the Forge machinery. Everything else is grown when required.
3. **The agent is an untrusted proposer.** The model may write, adapt,
   diagnose, and optimize. Candidate code never authorizes itself; every
   candidate passes deterministic admission gates.
4. **Admission is not permission.** A verified, reversible capability (for
   example a camera driver) may be admitted automatically. Using it for
   privacy, external communication, destructive storage changes, security
   roots, encryption, credentials, identity, or other irreversible effects
   still requires owner policy through AEGIS. The owner approves durable
   policies rather than individual interruptions.
5. **No native admission without enforcement.** Generated native components
   run on the physical machine only after enforceable memory, DMA (SMMU), and
   capability isolation exist (M3). Before that, a candidate can prove only
   that it passed every test we know how to run.
6. **Generations.** Every accepted system state is an immutable, numbered
   Generation recording: parent, source provenance, build provenance, code
   hashes, tests, proof receipts, capability grants, hardware target,
   benchmark evidence, and rollback target. Activation is inactive-slot plus
   canary promotion. Failure never destroys the previous accepted Generation.
   Recovery never requires a model.
7. **Two records per capability.**

   ```text
   Capability Artifact    what was built: source and provenance, supported
                          hardware constraints, tests, known proofs and failures
   Capability Admission   this MachineId, this firmware/hardware state, the
                          local verification receipt, the granted resource
                          envelope, the Generation it entered
   ```

8. **Knowledge is shareable; trust is not transferable.** Artifacts move
   freely between the owner's machines and, later, through a public
   content-addressed commons between people. A proof on machine A is evidence,
   not authority, for machine B: every receiving machine rebuilds or
   reproduces where practical, checks hardware/firmware prerequisites, reruns
   the deterministic tests, runs its own constrained canary, and issues its
   own admission. Exact hardware/firmware matches may shorten validation.
   Source is preferred; prebuilt binaries are caches that must trace back to
   source and build provenance.
9. **Outside code enters as source.** Externally sourced code enters as
   auditable source with provenance. Runtime dependence on arbitrary Internet
   code is forbidden.
10. **Rollback first, repair second.** When a live capability violates its
    health contract, AIEN quarantines it and restores the most recent
    known-good Generation without waiting for the owner, preserves the
    evidence, diagnoses in an isolated World, and promotes a repair only
    through the normal proof pipeline and canary. Repeated failed repairs stop
    and are reported; there is no endless self-modification loop. For
    security-sensitive anomalies: revoke access first, investigate second.
11. **Honest failure, then compatibility, then optional escalation.** When AIEN
    cannot build a capability it says so plainly and why. If the owner allows
    it, a sealed incumbent-OS island may provide the capability temporarily
    (e.g. `camera.native unavailable`, `camera.compat.win available`). With
    explicit permission only, AIEN may publish a sanitized failure package to
    the commons. Compatibility fills gaps; it never becomes a hidden permanent
    dependency and stays visible as debt Forge keeps working to remove.
12. **Incumbent OS as scaffolding.** Per ADR 0002, an `aien-bootstrap` path may
    start inside Windows, macOS, or Linux as the normal entry for new machines:
    inspect the machine, build the Machine Capsule, allocate AIEN storage, run
    Forge, import data, and prepare the first native Generation. The Seed must
    boot independently and survive deletion of the incumbent OS. Machine 1 has
    already crossed into native execution and does not regress to this path.
13. **Owner-priority resource budget.** Forge runs any time but yields to the
    person immediately, under an explicit compute budget: small while the
    owner is active, larger while idle, temporarily raised (with visible
    status) for an urgent request. Values are learned per owner and machine,
    not hard-coded. Natural statements ("use everything overnight", "not while
    I'm gaming") compile into explicit resource policy.
14. **Execution state is bounded; provenance is permanent.**

    ```text
    PERMANENT                    Generation manifests, provenance, hashes,
                                 proof receipts, security events,
                                 migration/identity history,
                                 owner-important records
    PINNED UNTIL OWNER RELEASES  preserved Generations, major migration and
                                 recovery checkpoints
    FULLY RESTORABLE WINDOW      current Generation + the most recent
                                 known-good Generations (e.g. 3-5)
    RECLAIMABLE                  superseded binaries, duplicate build outputs,
                                 test environments, caches, model
                                 reconstruction state, abandoned candidates
    ```

    Storage is content-addressed: shared objects are stored once and collected
    only when nothing retained references them. Security rollback history and
    identity continuity records are never collected for age.

### Roadmap

```text
M0 / M1 / M2
 -> SEED-0A  Self-construction lab (now)
 -> M3       Kernel isolation: the enforcement substrate
 -> SEED-0B  Native capability admission
 -> M4+
```

**SEED-0A** can run now: the agent observes the machine, writes or adapts
code, builds reproducibly, runs the deterministic checks, tests in QEMU,
benchmarks, produces a proof receipt, and creates an *inactive* candidate
Generation. It does not claim the candidate is safe to run unrestricted on
hardware. Experiment #1 is `input.keyboard.usb` (#58). The Machine 1 hardware
test rig (ADR 0011) is the physical admission lab that later closes the loop:
candidate, proof, QEMU canary, Machine 1 lock, staged one-time boot, HDMI and
UART capture, automated verdict, automatic rollback.

**SEED-0B** follows the M3 isolation pieces (MMU, SMMU/DMA isolation,
exception boundaries, interrupt ownership, capability handles, task isolation,
resource accounting): generated code is admitted into a constrained world on
the physical machine, canaried, and promoted or destroyed.

## Consequences

- M3 is built as the enforcement substrate for generated code, not only as a
  conventional kernel milestone. Its acceptance should include "a candidate
  component can be confined to named pages, DMA windows, and devices".
- Every later milestone delivers mechanisms plus the capabilities of the
  survival kit, not a universal feature set.
- Evidence rules tighten for agents: a candidate's proof states what was
  tested (QEMU, host, hardware) and never implies hardware behavior it did not
  observe.
- The hardware test rig (ADR 0011) becomes a priority, since it turns the
  physical step from an operator task into an automated gate.
- Capability records, Generation manifests, and the retention tiers become
  persistent formats; their concrete schemas need their own ADRs before M4
  storage work fixes them.
- The owner is not the system administrator: AIEN is highly autonomous about
  engineering, conservative about authority, and nearly invisible about
  maintenance.
