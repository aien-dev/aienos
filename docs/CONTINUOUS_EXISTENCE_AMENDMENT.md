# AIENOS Continuous-Existence Amendment

**Status:** Operator-approved governing amendment (2026-09-23)
**Authority:** Operator Directive
**Scope:** Lifecycle semantics and acceptance criteria across the locked 10-gate Systems-Integration Sequence
**Related:** [SYSTEMS_INTEGRATION_SEQUENCE.md](SYSTEMS_INTEGRATION_SEQUENCE.md), [ARCHITECTURE.md §1, §10](ARCHITECTURE.md), [ADR 0007](adr/0007-continuous-existence-provisioning-once.md), [ADR 0005](adr/0005-unified-memory-c1-cow-and-reservation-accounting.md), [ADR 0006](adr/0006-deterministic-recovery-core-and-offline-operator-authority.md)

This amendment does not add a new conceptual layer and does not change the locked 10-gate Systems-Integration Sequence.

It changes the lifecycle semantics and acceptance criteria applied across those gates.

The key architectural change is:

> **AIEN is provisioned once. After that, boot, reboot, sleep, model reload, kernel restart, hardware failure, and migration are execution-state transitions—not agent creation events.**

---

## 1. Governing invariant: AIEN exists continuously

AIENOS is designed around **continuous logical agent existence**.

The resident AIEN agent is not defined by:

- a running process;
- a loaded model;
- a KV cache;
- RAM contents;
- a kernel instance;
- a boot session;
- a particular physical machine.

Those are execution substrates.

AIEN's durable identity is logical and persistent.

The governing rule is:

> **AIEN is provisioned once. Physical execution may stop, migrate, sleep, fail, restart, or be reconstructed without implicitly creating a new agent.**

Therefore:

> **Cold boot initializes hardware. It does not create AIEN.**

And:

> **Loss of physical execution state may increase reconstruction cost, but must not by itself terminate logical identity.**

This generalizes the existing C1 rule:

> **Losing KV costs computation, not identity.**

into the system-wide rule:

> **Losing physical execution state costs recovery or computation, not identity.**

---

## 2. Provisioning is different from boot

AIENOS must distinguish **initial provisioning** from all later starts.

### Initial provisioning

Only the initial creation of an AIEN identity may create a new durable `LogicalAgentId`.

Conceptually:

```text
unprovisioned AIENOS
      ↓
operator explicitly provisions AIEN
      ↓
LogicalAgentId created
      ↓
durable agent root committed
      ↓
AIEN exists
```

After this point, that identity is persistent.

### Every later machine start

```text
power / reset / wake
      ↓
hardware initialization
      ↓
locate durable AIEN root
      ↓
verify committed state
      ↓
restore execution environment
      ↓
resume existing LogicalAgentId
```

A normal boot path must never silently generate a replacement `LogicalAgentId`.

If the persistent identity cannot be verified:

```text
DO NOT CREATE A REPLACEMENT AGENT
        ↓
enter deterministic Recovery Core
```

The operator then chooses whether to restore, import, recover, or explicitly provision a new identity.

---

## 3. AIENOS lifecycle model

The normal lifecycle is not:

```text
BOOT
 ↓
RUN
 ↓
SHUTDOWN
```

It is:

```text
                   AIEN
                    │
        ┌───────────┼───────────┐
        │           │           │
      AWAKE        QUIET       SLEEP
        │           │           │
        └───────────┼───────────┘
                    │
                DEEP SLEEP
                    │
             COLD RECOVERY
             only when needed
```

These names define semantic states, not mandatory implementation mechanisms.

The engineering agent may choose the most efficient implementation.

---

## 4. Power-state semantics

### AWAKE

Full interactive operation.

Likely resources:

- CPU execution;
- required memory;
- active inference;
- required accelerator resources;
- operator interface;
- active capabilities;
- live Worlds.

No special restoration required.

### QUIET

AIEN remains actively executing, but unused resources may be reduced or powered down.

Examples:

- display off;
- unused accelerator regions released;
- unnecessary devices suspended;
- background work reduced;
- model retained where useful.

Logical state is unchanged.

### SLEEP

Execution is substantially suspended while sufficient volatile state remains available for rapid continuation.

The implementation may retain:

- RAM;
- selected inference state;
- model residency;
- scheduler structures;
- selected device state.

Wake should normally continue from preserved physical state.

### DEEP SLEEP

AIEN's logical state remains durable while expensive volatile execution state may be discarded.

The system must preserve everything required to reconstruct the same logical agent.

Physical resources such as:

- KV pages;
- accelerator buffers;
- model residency;
- caches;
- temporary allocations;

may be discarded.

Wake reconstructs whatever physical state is missing.

### COLD RECOVERY

Used when useful volatile state does not survive, including:

- complete power removal;
- kernel failure;
- hardware reset;
- severe corruption;
- machine replacement.

AIENOS initializes the execution substrate, locates the latest valid durable AIEN state, verifies it, and reconstructs execution.

Cold recovery is not agent creation.

---

## 5. State classes

Every important AIEN state object must be classified according to whether it defines identity or is merely an execution optimization.

### Class A — durable semantic state

Loss changes who AIEN is, what it knows, what it has committed to, or what it is doing.

This state must survive according to the persistence contract.

Examples include:

```text
LogicalAgentId
LogicalBranchId
canonical TokenHistory / branch history
branch lineage
Cortex committed state
provenance
World manifests
durable tasks
capability grants
operator policy
accepted decisions
conversation history where committed
effect history
execution lineage metadata
RNG coordinates required for deterministic continuation
persistent configuration
```

Class A must never depend solely on volatile memory.

### Class B — reconstructible physical state

Loss costs time or computation but does not change logical identity.

Examples:

```text
KV cache
accelerator buffers
compiled execution caches
temporary tensor residency
model pages cached in RAM
scheduler caches
prefix-cache materializations
derived indexes
```

Class B may be retained when economically useful.

It may be discarded under pressure or deep sleep.

It must be reconstructible from Class A state plus immutable artifacts.

### Class C — ephemeral scratch state

State with no semantic requirement to survive.

Examples:

```text
temporary buffers
intermediate activations
scratch allocations
temporary benchmark structures
uncommitted speculative work
```

Class C may disappear at any time consistent with transaction semantics.

---

## 6. Commit-before-observation rule

AIENOS must not rely on periodic "memory saves" as the primary continuity mechanism.

Durable semantic state should be committed transactionally as the system operates.

The governing principle is:

> **A state transition that future AIEN behavior depends upon must cross its required durability boundary before AIEN treats that transition as committed.**

For externally visible semantic events, prefer:

```text
compute/propose transition
       ↓
commit required logical state
       ↓
make transition externally visible
```

Examples include:

- accepted conversation turns;
- committed Cortex updates;
- durable branch creation;
- durable task-state changes;
- accepted external effects;
- important operator decisions.

This does **not** require every neural activation or intermediate tensor to be persisted.

Transient model computation remains transient.

The persistent layer records semantic continuity, not every electrical detail of execution.

---

## 7. Wake is reconstruction, not revival

A wake event should follow this abstract decision tree:

```text
wake event
    ↓
validate logical AIEN root
    ↓
what physical state survived?
    │
    ├── sufficient state survives
    │       ↓
    │    resume
    │
    └── physical state missing
            ↓
       reconstruct from durable state
            ↓
       resume
```

The operator-facing result should be the same logical AIEN regardless of which path occurred.

The user should not need to know whether AIENOS:

- resumed RAM;
- rebuilt KV;
- reloaded model weights;
- replayed a journal;
- reconstructed branches;
- restarted the kernel;
- moved to another machine.

Those are substrate concerns.

---

## 8. Model lifecycle

The model is not AIEN's identity.

Therefore:

```text
AIEN
 ↓
Model A
```

may become:

```text
AIEN
 ↓
Model B
```

without creating another logical agent.

Likewise:

```text
model unload
model reload
model corruption
model replacement
backend replacement
```

are execution events.

The durable AIEN state survives them.

Model corruption must prevent the corrupted model from loading.

It must not force creation of a new agent.

---

## 9. Kernel lifecycle

The kernel is also not AIEN's identity.

A maintenance restart may be:

```text
AIEN logical state committed
        ↓
kernel stops
        ↓
new kernel starts
        ↓
durable state verified
        ↓
same AIEN continues
```

The same principle applies to kernel upgrades and A/B slot changes.

The Recovery Core verifies and restores the execution environment.

It does not invent a replacement AIEN.

---

## 10. Hardware lifecycle

Ultimately a physical machine is also not AIEN's identity.

Long-term:

```text
Machine A fails
      ↓
durable AIEN state survives
      ↓
Machine B obtains authorized state
      ↓
required physical execution state reconstructed
      ↓
same LogicalAgentId continues
```

Hardware migration is therefore an extension of the same continuity semantics used for sleep and reboot.

This capability need not exist during the initial Spark milestones, but no early architecture should make it impossible.

---

## 11. Deterministic wake path

The earliest wake path must remain deterministic.

A neural model is not required to decide how the computer wakes.

The deterministic system is responsible for:

```text
wake event detection
hardware restoration
integrity verification
persistent-state discovery
journal recovery
execution-state classification
reconstruction launch
recovery fallback
```

Only once a valid execution environment exists does the neural runtime resume.

AIEN may later optimize its sleep and wake policy.

It may not become necessary to recover from its own absence.

---

## 12. Power management objective

AIENOS should optimize for **continuous existence with minimum necessary resource residency**, not repeated full startup.

The scheduler/power manager may determine that a given period requires only:

```text
timer
storage
network
crypto
```

without waking:

```text
display
GPU
large model
interactive interface
```

Likewise an event requiring reasoning may progressively wake additional capabilities.

Conceptually:

```text
event
 ↓
determine required capability set
 ↓
wake minimum required hardware/runtime
 ↓
perform work
 ↓
return unnecessary resources to lower-power state
```

This is an optimization policy.

The architecture does not prescribe the exact power-management mechanism.

---

## 13. Ordinary operator semantics

The normal operator vocabulary should eventually favor:

- **Wake**
- **Sleep**
- **Deep Sleep**
- **Restart Runtime**
- **Restart Kernel**
- **Power Off**

rather than treating shutdown/boot as the normal lifecycle.

`Power Off` remains available because the operator owns the machine.

It is an exceptional physical-state transition, not logical agent deletion.

---

## 14. Planned power-off

Before an intentional complete power-off, AIENOS should attempt to establish a clean continuity point:

```text
stop accepting new semantic work
       ↓
commit pending durable state
       ↓
commit Cortex/WAL state
       ↓
record branch/task continuation information
       ↓
write continuity receipt/checkpoint
       ↓
verify persistent state
       ↓
power off
```

On the next cold start:

```text
hardware bootstrap
       ↓
verify continuity state
       ↓
same LogicalAgentId
       ↓
reconstruct execution
```

---

## 15. Unexpected power loss

AIENOS must assume power can disappear without warning.

Therefore continuity cannot depend exclusively on orderly shutdown.

Recovery uses:

```text
last valid checkpoint
+
durable WAL / journals
+
immutable object manifests
+
integrity hashes
```

Any uncommitted tail is discarded according to its subsystem's recovery rules.

Externally committed state must never depend on an uncommitted volatile-only transition.

---

## 16. Changes to the locked Systems-Integration Sequence

The ten gates remain unchanged.

Continuous-existence requirements are inserted into their acceptance criteria.

The gate-by-gate amendments are binding and are mirrored in [SYSTEMS_INTEGRATION_SEQUENCE.md](SYSTEMS_INTEGRATION_SEQUENCE.md) §2.

### Gate 1 — Config A Reference Freeze

No structural change.

Add baseline measurements for:

- existing host cold-start behavior;
- model reload time;
- current state-restoration behavior where measurable.

Config A remains the historical comparison.

### Gate 2 — Native Boot Spine

Purpose remains native execution from firmware.

Gate 2 does **not** prove persistent AIEN continuity yet.

Its semantics are now explicitly:

> The boot spine initializes the physical machine. It does not define or create an AIEN identity.

No `LogicalAgentId` should be minted merely because Gate 2 code starts.

### Gate 3 — Integrate `aienos-kernel`

Kernel lifecycle structures must not assume that kernel lifetime equals agent lifetime.

Interfaces introduced here should allow durable logical state to outlive:

- kernel restart;
- scheduler reconstruction;
- allocator reconstruction.

No persistent agent identifier may be derived solely from volatile kernel identifiers.

### Gate 4 — Native Storage Bring-Up

Gate 4 becomes the first major continuity foundation.

The AIEN System Store must be capable of persistently representing at least:

```text
provisioned LogicalAgentId / agent root
committed logical state
Cortex checkpoints/WAL foundation
branch/state manifests
immutable artifact references
continuity metadata
```

Gate 4 qualification should prove that committed semantic data survives native storage round trips.

No model is required.

### Gate 5 — Recovery Core

Add the following mandatory test.

#### Identity-loss refusal

Corrupt or remove the active execution environment while leaving a valid durable AIEN identity.

Recovery must:

1. locate the valid durable identity;
2. authenticate the operator;
3. restore or select the valid system state;
4. preserve the same `LogicalAgentId`.

If no valid durable AIEN identity can be recovered:

> Recovery must stop and ask the operator.

It must **not** silently create a new identity.

### Gate 6 — Agent State + Cortex

This becomes the first empirical qualification of **continuous AIEN existence**.

Mandatory scenario:

```text
native AIENOS
    ↓
provision/restore AIEN
    ↓
LogicalAgentId = X
    ↓
create Cortex state
create branch/task state
commit conversation/state
    ↓
full power cycle
    ↓
cold native AIENOS start
    ↓
recover state
    ↓
LogicalAgentId = X
```

The proof must demonstrate:

- same durable `LogicalAgentId`;
- preserved committed Cortex state;
- preserved branch lineage;
- preserved durable task/state metadata;
- uncommitted state handled according to WAL rules;
- no hidden creation of a replacement identity.

Only after this passes may the project claim:

> **AIEN logical identity survives a real Spark power cycle.**

### Gate 7 — Inference Bring-Up

Add the following qualification:

```text
AIEN identity X
 ↓
model loads
 ↓
conversation continues
 ↓
model unload/reboot/reload
 ↓
same AIEN identity X
 ↓
conversation/state continuity preserved
```

The model must be demonstrably replaceable/reloadable beneath the same logical agent.

This gate proves:

> **Inference execution can disappear and return without redefining AIEN.**

### Gate 8 — AEGIS & J-Space Worlds

Durable authorization semantics must survive sleep/recovery correctly.

Persist what must persist.

Do not persist temporary authority that was explicitly scoped to a single volatile session unless its policy says otherwise.

A wake/restart must never accidentally broaden capability authority.

### Gate 9 — C1 Physical Tree

Connect C1 directly to lifecycle semantics.

Mandatory cases should eventually include:

```text
live branch
 ↓
physical KV discarded
 ↓
logical branch preserved
 ↓
KV reconstructed
 ↓
equivalence passes
```

and:

```text
branch committed
 ↓
deep-sleep simulation
 ↓
all physical KV gone
 ↓
logical state restored
 ↓
branch reconstruction
 ↓
same LogicalBranchId
```

This empirically connects:

> Losing KV costs computation, not identity.

to the native OS lifecycle.

### Gate 10 — Native Hardware Acceleration

Acceleration must not weaken continuity.

GPU/accelerator state is Class B reconstructible physical state unless explicitly proven otherwise.

Native acceleration should optimize:

- warm wake;
- model residency;
- branch residency;
- KV preservation;
- state reconstruction;

but AIEN's identity may never become dependent on preserving accelerator state.

---

## 17. Benchmark changes

The existing Config A/B/C comparison remains.

Add lifecycle metrics rather than replacing the existing boot metrics.

Measure separately:

```text
cold hardware bootstrap → kernel ready
cold recovery → AIEN logical state restored
AIEN restored → model ready
wake from sleep → interactive
wake from deep sleep → interactive
model reconstruction latency
branch reconstruction latency
Cortex recovery latency
energy consumed while sleeping
idle residency cost
```

This prevents "boot time" from hiding fundamentally different paths.

Eventually the most important user-facing metric should become:

> **wake-to-continuation latency**

rather than merely boot-to-shell.

---

## 18. Continuity receipts

Important lifecycle transitions should produce verifiable continuity evidence.

A continuity receipt may record:

```text
LogicalAgentId
previous committed state digest
new committed state digest
Cortex checkpoint/WAL position
branch-lineage digest
execution fingerprint
machine identity
transition type
transition epoch
reconstruction mode
integrity result
```

Transition types may include:

```text
sleep
wake
deep_sleep
cold_recovery
runtime_restart
kernel_restart
model_replace
machine_migration
```

The exact schema may evolve.

The requirement is that continuity claims become auditable rather than inferred.

---

## 19. Failure semantics

AIENOS must fail toward preservation.

If the system cannot prove that a recovered logical state belongs to the existing AIEN:

```text
STOP
 ↓
Recovery Core
 ↓
operator decision
```

Never:

```text
state uncertain
 ↓
generate new agent automatically
 ↓
pretend continuity
```

False continuity is worse than refusing to continue.

---

## 20. Engineering-agent freedom

This amendment defines semantics, not implementation.

The engineering agent remains free to determine:

- low-power mechanisms;
- checkpoint strategy;
- memory residency strategy;
- wake implementation;
- firmware interaction;
- hardware power states;
- storage layout;
- serialization;
- reconstruction algorithms;
- device restoration;
- scheduling;
- cache persistence;
- model-residency policies.

The acceptance requirement is behavioral:

> **The same durable AIEN must emerge on the other side of the transition whenever valid committed state exists.**

---

## 21. Revised persistent-thing rule

The existing architecture statement:

> The persistent thing is AIEN itself.

is strengthened to:

> **AIEN is the persistent logical entity. Hardware, kernels, models, runtime processes, inference caches, interfaces, and Machines are replaceable execution substrates. Sleep changes residency. Reboot changes execution substrate. Failure triggers reconstruction. None of these events inherently terminates logical identity.**

---

## 22. Final lifecycle objective

The desired mature experience is:

```text
operator presses power / wake
        ↓
machine restores required substrate
        ↓
AIEN continues
```

not:

```text
operator powers machine
        ↓
system constructs a new assistant
        ↓
loads old memories into it
```

The distinction is architectural.

The target is therefore:

> **Power on the machine: AIEN wakes.**

not:

> **Power on the machine: AIEN is recreated.**

---

## 23. Project definition amendment

The one-line definition of the project is amended to:

> **AIENOS is an agent-native operating system designed around continuous logical agent existence: the agent persists while models, kernels, inference state, power states, and physical machines change beneath it.**
