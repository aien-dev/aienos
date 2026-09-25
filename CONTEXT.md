# AIENOS Domain Model

AIENOS is an agent-native, sovereign operating system wherein the persistent AIEN agent is the primary user interface and control plane, running directly on bare-metal hardware.

## Language

### Core Entities

**Operator**:
The sovereign human user who owns the hardware, sets ultimate policy, and holds root authority over the system.
_Avoid_: User, admin, root, consumer

**AIEN Agent**:
The persistent logical intelligence entity that acts as the primary interface, planner, and coordinator for the machine across reboots and hardware changes.
_Avoid_: Assistant, bot, chatbot, process

**Logical Agent Identity**:
The immutable cryptographic and semantic identity (`LogicalAgentId`, lineage, token history, provenance) that persists across hardware swaps, crashes, and reboots. Created only by initial provisioning; boot, sleep, model reload, kernel restart, and migration resume it—they do not create it (Continuous-Existence Amendment).
_Avoid_: PID, session, instance, thread, recreated agent

**Physical Execution State**:
The ephemeral, disposable hardware state (KV cache pages, GPU buffers, scheduler slots, registers) utilized to run inference.
_Avoid_: Agent identity, persistent state

**Kernel**:
The minimal, deterministic, auditable software layer that schedules CPU, manages memory, services interrupts, and enforces capabilities without requiring an AI model.
_Avoid_: Core, microkernel, executive

**Binary Artifact**:
An externally supplied executable package with an authenticated identity, an explicit request for bounded authority, and an explicit resource envelope.
_Avoid_: Binary, program, module (when referring to an admitted executable package)

**ArtifactId**:
The stable cryptographic identity of a Binary Artifact's canonical execution contract and exact payload bytes.
_Avoid_: File hash, signer identity

**Model**:
A replaceable, swappable intelligence component accessed via the Model ABI that proposes thought and action without possessing inherent authority.
_Avoid_: Operating system, AI, brain

---

### Security & Authority

**AEGIS**:
The deterministic policy evaluation and capability enforcement system that evaluates whether an agent's proposed action is permitted.
_Avoid_: Firewall, permission manager, sudo

**Capability**:
An unforgeable token granting fine-grained authority to access a specific resource or effect.
_Avoid_: Privilege, role, access right

**Capability Request**:
A Binary Artifact's bounded request for particular rights over one named resource; it grants no authority until local policy admits it.
_Avoid_: Permission mask, capability grant

**Granted Admission**:
The deterministic authorization result that intersects verified Capability Requests with local policy and available resources.
_Avoid_: Artifact permission, trust decision (when referring to the resulting resource handles)

**Admission Receipt**:
A cryptographically signed record binding an ArtifactId to its verification, policy decision, requested and granted authority, resources, and execution result.
_Avoid_: Log line, boot report

**EffectIntent**:
A structured proposal emitted by the agent expressing a desire to perform an action on the physical machine, network, or data.
_Avoid_: Command, system call, RPC

**EffectBroker**:
The deterministic mechanism that translates an AEGIS-authorized EffectIntent into real physical hardware, driver, or network effects.
_Avoid_: Dispatcher, driver wrapper

---

### Epistemics & Execution

**Cortex**:
The persistent, evidence-aware knowledge system that records facts, observations, and decisions with verifiable provenance.
_Avoid_: Vector database, memory store, cache

**World**:
A sandboxed, reversible execution environment where the agent can mutate files, build code, run experiments, and evaluate decisions with instant rollback.
_Avoid_: Container, VM, workspace

**Irreversible Boundary**:
Any state change, network transmission, or physical action that permanently alters data, leaves the local fabric, or cannot be rolled back via World discard.
_Avoid_: Write operation, side effect

**C1 Copy-On-Write Tree**:
The branch-native prefix sharing architecture that shares common physical inference KV pages across divergent reasoning branches, allocating private pages only on divergence.
_Avoid_: Prefix cache, KV cache

**Machine Capsule**:
A portable hardware description generated on a host system that defines all CPU, accelerator, storage, memory, and firmware characteristics required for AIENOS to reproduce native execution.
_Avoid_: Hardware profile, sysinfo

---

### Storage, Recovery & Allocation

**AIEN System Store**:
The native, minimal persistent storage layer organizing immutable content-addressed extents, append-only journals, and committed agent states without general-purpose POSIX filesystem overhead.
_Avoid_: Filesystem, disk image, partition table

**Recovery Core**:
The deterministic, non-model operating environment providing local operator authentication, A/B slot verification, rollback, and raw hardware diagnostics without AI dependencies.
_Avoid_: Recovery mode, safe mode, rescue shell

**Standing Capability**:
A pre-authorized capability grant enabling autonomous agent execution of specific external effects without interactive per-action confirmation.
_Avoid_: Permanent privilege, whitelist

**Transactional KV Reservation**:
An atomic memory reservation acquired prior to scheduling a reasoning step to guarantee that worst-case private block divergence cannot exhaust physical memory mid-step.
_Avoid_: Dynamic allocation, malloc
