# AIENOS — Final Architectural Blueprint

> **Foundational Mandate to the Engineering Agent:**  
> *“You own the route; this document owns the destination.”*

## 1. The final vision

AIENOS is an agent-native operating system.

The end state is a machine where the user presses the power button and AIEN wakes up directly.

Not:

Windows → AIEN application.

Not:

macOS → AIEN application.

Not:

Ubuntu → desktop → containers → Python → HTTP server → AIEN.

The target is:

```text
Power
  ↓
Firmware
  ↓
AIEN Boot Trust
  ↓
AIENOS
  ↓
Hardware
  ↕
AIEN Runtime
  ↕
Persistent AIEN Agent
  ↓
User
```

AIEN itself is the persistent thing.

The physical computer can change.

The model can change.

The GPU can change.

The user interface can change.

Individual implementations can change.

But the agent's identity, state, memory, authority, history, evidence and relationship to the operator survive those changes.

The computer is no longer organized around applications.

It is organized around:

```text
identity
state
memory
capabilities
effects
hardware
models
Worlds
evidence
```

The model is an intelligence component inside the system.

It is not the operating system.

It is not the root of trust.

It is not the authority that decides what it is allowed to do.

---

# 2. The central architectural principle

AIENOS separates four things that conventional AI systems usually blur together:

```text
WHO AM I?
    ↓
Persistent logical agent identity

WHAT DO I KNOW?
    ↓
Cortex / evidence-aware memory

WHAT AM I ALLOWED TO DO?
    ↓
AEGIS / capabilities / effect authorization

WHERE AM I CURRENTLY EXECUTING?
    ↓
Physical compute, inference state, memory and hardware
```

Those must remain separable.

The foundational rule remains:

> Losing physical inference state should cost computation, not identity.

A GPU crash must not create a new agent.

Evicting KV memory must not create a new agent.

Changing models must not create a new agent.

Rebooting the computer must not create a new agent.

Moving to another machine must eventually not create a new agent.

Physical execution is replaceable.

Logical identity is persistent.

---

# 3. Final system architecture

The target stack is approximately:

```text
┌────────────────────────────────────────────┐
│                  OPERATOR                  │
└─────────────────────┬──────────────────────┘
                      │
┌─────────────────────▼──────────────────────┐
│               AIEN AGENT                  │
│                                            │
│ reasoning • planning • interface • routing │
└──────────┬───────────┬───────────┬─────────┘
           │           │           │
           ▼           ▼           ▼
       J-Space      Cortex     Capability
        Worlds      Memory        Graph
           │           │           │
           └───────────┼───────────┘
                       ▼
┌────────────────────────────────────────────┐
│                   AEGIS                    │
│                                            │
│ policy • authorization • provenance        │
│ effect approval • capability enforcement   │
└─────────────────────┬──────────────────────┘
                      │
                      ▼
┌────────────────────────────────────────────┐
│              EFFECT BROKER                 │
│                                            │
│ converts authorized intent into real       │
│ effects on machines, networks and data     │
└─────────────────────┬──────────────────────┘
                      │
┌─────────────────────▼──────────────────────┐
│             AIEN NEURAL RUNTIME            │
│                                            │
│ Model ABI                                  │
│ Agent State ABI                            │
│ inference scheduler                        │
│ physical COW state                         │
│ placement / compute                        │
│ tools and skills                           │
│ storage services                           │
│ network services                           │
└─────────────────────┬──────────────────────┘
                      │
┌─────────────────────▼──────────────────────┐
│              AIENOS KERNEL                 │
│                                            │
│ scheduling                                 │
│ memory                                     │
│ IPC / capabilities                         │
│ interrupts                                 │
│ storage                                    │
│ networking                                 │
│ device access                              │
│ isolation                                  │
│ recovery                                   │
└─────────────────────┬──────────────────────┘
                      │
┌─────────────────────▼──────────────────────┐
│                  HARDWARE                  │
│ CPU • GPU/NPU • RAM • disks • network • IO │
└────────────────────────────────────────────┘
```

The exact implementation of every box may change.

The separation between the boxes should not.

---

# 4. What is fixed versus what the engineering agent may decide

The engineering agent should have substantial autonomy.

It may choose:

* algorithms;
* data structures;
* crate boundaries;
* internal APIs;
* schedulers;
* allocator designs;
* boot mechanisms;
* storage implementations;
* driver strategies;
* build tooling;
* testing machinery;
* optimization techniques;
* assembly versus Rust versus another appropriate open technology;
* whether a component should initially be replaced, wrapped, emulated or rewritten;
* the fastest technically sound path to the milestone.

The agent should not be forced to implement something merely because we previously imagined one implementation.

The architecture is defined by behavior and boundaries, not by arbitrary code layout.

What is not free to drift is the destination.

AIENOS must remain independently bootable.

The agent cannot become the root of trust.

Native AIENOS cannot require Windows, macOS or Linux to survive.

The trusted core cannot require a proprietary cloud service, licensing server or opaque compiler/runtime to boot, recover or control the machine.

Compatibility infrastructure cannot quietly become the permanent native architecture.

Operator authority cannot be silently broadened.

Persistent identity cannot be reduced to a running process ID.

Correctness cannot be sacrificed merely because an implementation benchmarks faster.

Everything else is engineering territory.

---

# 5. Boot and trust architecture

Eventually:

```text
Firmware
    ↓
operator-controlled boot trust
    ↓
verified AIENOS boot artifact
    ↓
verified kernel
    ↓
verified system services
    ↓
verified AIEN Runtime
    ↓
persistent AIEN state
```

The operating principle is:

> The agent cannot authorize itself.

The model may propose:

> Send this email.

But the actual path is:

```text
Model proposes action
       ↓
EffectIntent
       ↓
AEGIS
       ↓
capability + policy evaluation
       ↓
Effect Broker
       ↓
driver / network / storage
       ↓
real-world effect
```

The intelligence that proposes an action is therefore separated from the deterministic mechanism deciding whether the action may occur.

That separation is fundamental.

---

# 6. The AIENOS kernel

The kernel should remain small relative to the whole AIEN system.

It does not need to reason.

It needs to be extremely dependable.

At maturity it owns things such as:

```text
CPU scheduling
memory management
interrupts
timers
IPC
capability enforcement
device access
storage
networking
isolation
process/service lifecycle
recovery
```

The model must not be necessary to:

* boot;
* mount storage;
* recover data;
* diagnose basic failures;
* authenticate the operator;
* repair the system;
* roll back an update;
* kill a malfunctioning service.

AIENOS must remain a functioning computer even if no model loads.

---

# 7. Hardware sovereignty

The long-term target is direct ownership of the important hardware path.

Conceptually:

```text
AIEN Runtime
     ↓
AIENOS native interfaces
     ↓
hardware
```

rather than:

```text
AIEN
 ↓
desktop application
 ↓
framework
 ↓
IPC
 ↓
host service
 ↓
general-purpose OS stack
 ↓
driver stack
 ↓
hardware
```

But this does not mean rewriting everything simply for ideological reasons.

The engineering agent should optimize toward the native path where it provides actual value.

The objective is:

```text
fewer copies
fewer boundaries
less serialization
less unnecessary scheduling
predictable latency
persistent model residency
direct memory management
direct accelerator state
direct storage paths
direct network paths
lower overhead
higher agent density
```

The project measures each of these instead of assuming bare metal is automatically faster.

---

# 8. Compatibility islands

During the transition, AIENOS is allowed to use compatibility islands.

For example:

```text
                AIENOS
                  │
       ┌──────────┴──────────┐
       │                     │
native capability     compatibility island
       │                     │
       ▼                     ▼
   hardware             Linux/vendor stack
```

An island can temporarily provide:

* GPU access;
* legacy applications;
* unsupported hardware;
* specialized vendor functionality.

It can even be faster than the native implementation temporarily.

That is acceptable.

What matters is:

> The island is not AIENOS's foundation.

Removing it must not make the native system impossible to build, boot, recover or control.

Over time:

```text
Era I
large compatibility island
small native system

Era II
rough parity

Era III
mostly native
small legacy island

End state
islands exist only where useful
```

---

# 9. Agent State ABI

This may become one of AIEN's most important contributions.

An agent should have logical state that is separate from whatever runtime instance happens to execute it.

The hierarchy becomes roughly:

```text
LogicalAgentId
      │
      ├── LogicalBranchId
      │
      ├── TokenHistory
      │
      ├── memory references
      │
      ├── capability state
      │
      ├── lineage
      │
      └── evidence/provenance
      │
      ▼
Execution incarnation
      │
      ▼
SequenceId
      │
      ▼
physical inference state
      │
      ├── KV pages
      ├── accelerator buffers
      └── temporary compute
```

A branch can:

```text
fork
run
suspend
resume
evict
reconstruct
crash
restart
```

without silently changing semantic identity.

Eventually:

```text
fork(agent_state)
checkpoint(agent_state)
suspend(agent_state)
resume(agent_state)
migrate(agent_state)
destroy(agent_state)
```

become well-defined system operations.

---

# 10. Copy-on-write agent computation

AIEN's branch model should allow many reasoning branches to share their common physical inference prefix.

Instead of:

```text
100 agents
×
same 100K-token prefix
```

AIEN aims toward:

```text
one physical prefix
        ↓
 ┌──────┼──────┬──────┐
 ↓      ↓      ↓      ↓
B1     B2     B3     ...
```

Only divergent state becomes private.

This potentially affects:

* coding-agent swarms;
* planning;
* search;
* hypothesis exploration;
* best-of-N inference;
* simulation;
* research agents;
* long-context reasoning.

C1 exists to prove this behaves correctly before AIEN makes strong performance claims around it.

---

# 11. Cortex

Cortex is the persistent knowledge system.

Its job is not merely to store embeddings.

It should maintain distinctions such as:

```text
observation
verified fact
source
inference
hypothesis
contradiction
decision
episodic memory
canonical state
```

The system should understand not just:

> What do I remember?

but:

> Why do I believe this?

That avoids a failure mode where model-generated speculation gets stored, later retrieved as apparent fact, and recursively reinforces itself.

Cortex becomes durable epistemic state.

---

# 12. Worlds / J-Space

AIEN needs a place where it can act freely without constantly asking permission.

The basic operating principle is:

> Free inside reversible state. Approval at irreversible boundaries.

A World is a reversible execution/state environment.

Inside one, AIEN can:

* modify code;
* restructure files;
* run tests;
* experiment;
* build artifacts;
* simulate decisions;
* change temporary configuration;
* create branches;
* evaluate alternative solutions.

Only when something needs to cross from reversible state into the real world does the Effect system become involved.

For example:

```text
World
  ↓
AIEN modifies repository
  ↓
tests pass
  ↓
AIEN proposes publish
  ↓
EffectIntent: push code externally
  ↓
AEGIS
  ↓
operator policy/approval
  ↓
Git operation
```

This allows considerable autonomy without making autonomy equivalent to unlimited authority.

---

# 13. Capability Graph

Traditional operating systems organize software around programs.

AIENOS should increasingly organize functionality around capabilities.

Examples:

```text
filesystem.read
filesystem.write

mail.read
mail.send

calendar.read
calendar.schedule

code.build
code.test
code.publish

network.connect

image.edit

model.run

device.camera

hardware.inspect
```

Applications may still exist.

But an application does not own the underlying capability or data.

The agent can compose capabilities dynamically.

That is how the computer stops being a collection of application silos and becomes an environment the agent can operate coherently.

---

# 14. Model ABI

Models are replaceable intelligence engines.

AIENOS should eventually be able to say:

```text
load model A

replace with model B

run specialist model C for coding

run smaller model D for routing
```

without redefining the identity of the agent.

The Model ABI should separate:

```text
model weights
tokenizer
execution backend
inference state
sampling
logical agent state
```

No model provider should become equivalent to AIEN itself.

---

# 15. Phase 1 — Freeze reality

Before replacing anything, freeze the working Spark system.

This is Config A.

```text
Ubuntu
   ↓
current AIEN stack
   ↓
current NVIDIA path
   ↓
DGX Spark
```

The goal is not optimization.

The goal is reproducibility.

Capture:

* hardware identity;
* firmware;
* current OS;
* source commits;
* build configuration;
* model hashes;
* tokenizer;
* libraries;
* execution environment;
* workloads;
* correctness evidence;
* recovery procedure;
* performance distributions.

Produce a verified reference bundle.

After this phase we can answer:

> What exactly did native AIENOS replace?

without relying on memory or marketing.

---

# 16. Phase 2 — Native AIENOS boot

Now the actual operating system begins.

Objective:

> Power on the DGX Spark and boot AIENOS itself.

Minimum milestone:

```text
Firmware
 ↓
AIENOS boot
 ↓
AIENOS kernel
 ↓
CPU initialized
 ↓
memory available
 ↓
interrupts/timers operating
 ↓
console available
 ↓
storage available
 ↓
recovery available
```

No agent required yet.

No GPU required yet.

No elaborate UI required.

No networking required to claim this milestone.

The proof is brutally simple:

> The machine boots AIENOS without Linux being the host.

---

# 17. Phase 3 — The agent wakes up

Once the native machine substrate works:

```text
AIENOS boots
 ↓
AIEN Runtime starts
 ↓
local model loads
 ↓
AIEN Agent starts
 ↓
operator can communicate with it
 ↓
Cortex persists
 ↓
reboot
 ↓
same logical AIEN resumes
```

CPU inference is sufficient.

The objective isn't speed yet.

The objective is continuity.

The first native AIEN should primarily understand and operate AIENOS itself.

Its earliest job is:

```text
observe machine
diagnose machine
inspect itself
run tests
read logs
repair reversible failures
help develop AIENOS
```

General assistant capabilities are secondary during this stage.

---

# 18. Phase 4 — Native system intelligence

Now make the agent genuinely useful as the operating interface.

Bring in:

```text
Cortex
Agent State
AEGIS
Effect Broker
Capability Graph
Worlds
system introspection
storage capabilities
local tools
developer capabilities
```

The operator should increasingly be able to interact with the system through intent:

> Show me what's consuming memory.

> Fix this build.

> Find why networking stopped.

> Create a new development World.

> Roll back the last system update.

AIEN translates intent into capabilities rather than requiring the user to manually navigate traditional programs.

---

# 19. Phase 5 — Native hardware acceleration

Only after native AIENOS itself exists do we aggressively optimize.

AIENOS progressively takes ownership of hot paths:

```text
accelerator
storage
network
memory
scheduler
inference
```

The engineering agent is free to find the fastest correct solution.

The requirement is that the resulting native path remains sovereign according to the trusted-base rules.

Compatibility GPU paths can remain beside it while the native accelerator path matures.

The important competition becomes:

```text
A — Ubuntu reference
B — minimal Linux / compatibility island
C — native AIENOS
```

Run the same workloads.

Compare separately:

```text
boot → agent ready

agent ready → model ready

TTFT

steady-state throughput

memory availability

scheduler jitter

power

branch creation

branch physical memory cost

restore time

agent density
```

No single synthetic “speed score.”

---

# 20. Phase 6 — Migration system

Once AIENOS can survive independently, adoption becomes important.

The existing OS becomes an installer.

On Windows/macOS/Linux:

```text
AIEN bootstrap
      ↓
inspect machine
      ↓
Machine Capsule
      ↓
determine AIENOS support
      ↓
prepare native installation
      ↓
preserve user state
      ↓
install separate boot target
      ↓
validate
      ↓
Restart into AIEN
```

The host is scaffolding.

It is not the destination.

The core migration rule:

> AIENOS may learn from the host, but it must not require the host to survive.

---

# 21. Machine Capsule

A host-side AIEN installation should learn enough about a machine to create a portable description of it.

Conceptually:

```text
MachineCapsule
├── firmware
├── CPU
├── accelerator
├── memory
├── storage
├── network
├── display
├── audio
├── USB
├── Bluetooth
├── input
├── known drivers
├── user state
├── critical applications
└── compatibility requirements
```

The Machine Capsule is not itself a driver implementation.

It describes what AIENOS needs to reproduce.

The engineering agent may then determine the best path for supporting that machine.

---

# 22. Reversible installation

AIENOS should initially install beside the existing OS.

Conceptually:

```text
Disk
│
├── incumbent OS
│
├── AIENOS
└── recovery
```

The system validates:

```text
boot
storage
display
input
network where available
model loading
AIEN state
Cortex
recovery
```

before encouraging broader migration.

If AIENOS fails:

> Boot the old system.

This dramatically lowers adoption risk.

---

# 23. Progressive escape from the incumbent OS

At first, users may still rely on old software.

That's acceptable.

The progression is:

```text
Stage 1
AIEN lives inside host.

Stage 2
AIENOS dual-boots.

Stage 3
AIENOS becomes primary.

Stage 4
Legacy host is used only for a few applications.

Stage 5
Legacy capabilities run through compatibility islands.

Stage 6
Old OS becomes an archive/recovery image.

Stage 7
Old OS can be removed if the operator chooses.
```

The project does not force migration.

It makes migration increasingly unnecessary to resist.

---

# 24. Phase 7 — Multi-hardware AIENOS

Once Spark proves the architecture, expand outward.

Do not hard-code the system conceptually around NVIDIA DGX Spark.

Spark is the reference machine, not AIEN's identity.

Port AIENOS to additional targets based on engineering value and available resources.

Examples could eventually include:

```text
desktop x86
ARM systems
AMD accelerator systems
Apple hardware where practical
embedded systems
future AI appliances
```

Every platform implements the same higher-level AIEN contracts.

Hardware becomes a replaceable substrate.

---

# 25. Phase 8 — Personal Fabric

Eventually one AIEN may span several machines.

For example:

```text
                    AIEN
                      │
         ┌────────────┼────────────┐
         │            │            │
       Spark        Laptop        Phone
         │            │            │
        GPU         display       sensors
       compute       keyboard      mobile
```

Machines become resources belonging to the operator's AIEN environment.

AIEN can determine:

> This computation belongs on Machine A.

> This interface belongs on Machine B.

> These files remain physically on Machine C.

> This model should migrate to the workstation.

The identity remains above the machines.

---

# 26. Eventually: state mobility

A mature system should be able to:

```text
run branch on machine A
       ↓
suspend
       ↓
move logical state
       ↓
reconstruct required physical state
       ↓
resume on machine B
```

Physical KV state need not necessarily migrate byte-for-byte.

The system may decide recomputation is cheaper.

Again:

> Physical state is optimization.

> Logical state is identity.

---

# 27. Evidence architecture

Every major AIENOS technical claim should be backed by a reproducible evidence bundle.

That means:

```text
source commit
machine identity
build identity
model identity
config
workload
raw measurements
correctness result
environment
verifier
artifact hashes
```

No screenshot-as-proof culture.

No benchmark number detached from the command that generated it.

No “verified” because the program happened not to crash.

Claims should be predefined.

Evidence earns claims.

Evidence does not earn adjectives.

---

# 28. C1's role

C1 remains foundational.

Before AIENOS uses branch-native inference as a major architectural advantage, C1 establishes that:

```text
identity survives
branches isolate correctly
COW is physically real
recomputation is equivalent
memory conserves correctly
resources are reclaimed
parents survive child behavior
state continuity survives resource events
```

AIENOS can inherit those semantics.

It should not create weaker OS-specific versions.

---

# 29. Development model for the autonomous engineering agent

The engineering agent receives:

```text
CURRENT STATE
+
NEXT MILESTONE
+
ARCHITECTURAL INVARIANTS
+
ACCEPTANCE TESTS
```

Then it is free to solve the engineering problem.

It should be allowed to:

```text
research
prototype
rewrite
benchmark
discard approaches
change internal implementation
write new tools
run experiments
optimize
refactor
```

without repeatedly asking which exact function to create.

The operator is not the implementation router.

The operator owns the architecture.

The agent owns engineering execution.

Escalation happens when the agent discovers that success appears to require changing something fundamental, such as:

```text
trust model
operator authority
persistent identity semantics
security boundary
irreversible data format
native-vs-compatibility boundary
sovereignty requirement
licensing
recovery guarantees
external protocol contract
major architecture
```

Otherwise:

> Solve it.

---

# 30. Failure should change implementation, not the goal

Suppose native storage approach A doesn't work.

The agent tries B.

Suppose B is slow.

Try C.

Suppose the planned scheduler architecture turns out to be wrong.

Replace it.

Suppose Rust isn't appropriate for a tiny low-level section.

Use something appropriate.

The blueprint should not trap the project inside guesses made before the evidence existed.

The destination is fixed.

The route evolves.

---

# 31. “Fastest wins” properly defined

The rule is not:

> fastest benchmark result wins regardless of everything else.

It is:

> Among implementations that satisfy correctness, security, sovereignty and the required contract, the fastest measured implementation wins.

Conceptually:

```text
Correct?
  no → reject

Secure enough?
  no → reject

Sovereignty contract?
  no → compatibility-only

Passes interface/invariant tests?
  no → reject

Remaining candidates
  ↓
measure
  ↓
fastest wins
```

---

# 32. Self-improvement

Eventually AIEN should help improve AIENOS.

But it must not mutate its trusted foundation arbitrarily while running.

The model may:

```text
discover optimization
 ↓
create experimental World
 ↓
modify implementation
 ↓
build
 ↓
run correctness suite
 ↓
benchmark
 ↓
compare evidence
 ↓
produce candidate
```

Promotion remains controlled:

```text
candidate
 ↓
evaluation
 ↓
security checks
 ↓
signing
 ↓
deployment
 ↓
rollback available
```

AIEN may improve itself.

AIEN does not simply declare its own rewrite trustworthy.

---

# 33. What the finished system feels like

The user presses power.

AIENOS verifies itself.

The resident agent wakes.

The machine already knows:

```text
who the operator is
who the agent is
what hardware exists
what capabilities exist
what state existed before shutdown
what projects are active
what memories are trusted
what permissions have been granted
what branches are suspended
what models are available
```

The user doesn't need to open an application to begin computing.

They interact with AIEN.

If they need something visual, AIEN creates an interface.

If they need code built, AIEN invokes build capabilities.

If they need mail sent, AIEN invokes mail capabilities.

If they need a simulation, AIEN creates a World.

If more reasoning is useful, AIEN forks state.

If hardware state disappears, AIEN reconstructs it.

If another machine is better suited, AIEN eventually moves work there.

The operating system becomes the substrate of the agent rather than the collection of applications the user manually coordinates.

---

# 34. The adoption proposition

The message isn't:

> Throw away your computer and install an experimental OS.

It becomes:

> Let AIEN learn the machine you already own.

Then:

> Let AIEN build a native environment for it.

Then:

> Restart into AIEN.

Then eventually:

> The old operating system is no longer necessary.

The host exists to help AIEN escape the host.

---

# 35. The strategic endpoint

The largest possible outcome is not merely an AIEN-branded operating system.

It is the establishment of a different abstraction for personal computing:

```text
old model:

user
 ↓
applications
 ↓
operating system
 ↓
hardware


AIEN model:

operator
 ↓
persistent intelligent agent
 ↓
capabilities + Worlds + memory + authority
 ↓
AIENOS
 ↓
hardware
```

And underneath the agent:

```text
logical identity ≠ physical execution
knowledge ≠ speculation
intelligence ≠ authority
compatibility ≠ architecture
performance ≠ correctness
model ≠ agent
machine ≠ identity
```

Those separations are the real architecture.

---

# 36. The master execution sequence

The overall journey is:

```text
CURRENT AIEN
     ↓
PHASE 1
Freeze Linux/Spark reference
     ↓
PHASE 2
Native AIENOS boots
     ↓
PHASE 3
Persistent AIEN wakes natively
     ↓
PHASE 4
Cortex + AEGIS + Worlds + capabilities
     ↓
PHASE 5
Native high-performance hardware paths
     ↓
PHASE 6
Host-to-AIENOS migration compiler
     ↓
PHASE 7
Additional hardware
     ↓
PHASE 8
Personal multi-machine fabric
     ↓
MATURE AIENOS
Persistent sovereign agent-native computing
```

The phases may overlap when engineering reality makes that useful.

Their order expresses dependency, not bureaucracy.

The engineering agent may discover a better path.

It should take it if the architectural invariants and milestone proofs remain intact.

---

# 37. Final definition of success

AIENOS has achieved its core vision when all of these statements are true:

The machine can boot without Windows, macOS or Linux acting as its host.

AIENOS can recover without an AI model.

The AIEN agent survives reboot as the same logical entity.

Cortex survives and preserves evidence/provenance semantics.

The model can be replaced without replacing AIEN.

Agent inference state can be branched, suspended, reclaimed and reconstructed without changing logical identity.

The agent operates the machine through explicit capabilities.

Irreversible effects cross enforceable authorization boundaries.

The operator can recover from AIEN failure.

No outside company is required for ordinary continued operation.

Important native hardware paths are directly controlled by AIENOS.

Compatibility layers are optional rather than foundational.

The system can prove its important performance and correctness claims.

The user can move to another supported machine without the idea of “their AIEN” being tied permanently to the old hardware.

And the ordinary experience becomes:

> Power on the machine. AIEN wakes up.

That is the final vision.
