# AIENOS Governing Architecture

Status: confirmed by the operator on 2026-09-23. Changes to anything in this document that the operator listed as fundamental (see "Authority and escalation") require the operator's approval.

For complete architectural specifications, execution milestones, and decision records, see:
- [AIENOS Final Architectural Blueprint](BLUEPRINT.md) (Complete 37-section architectural foundation)
- [AIENOS Architectural Milestones Matrix](MILESTONES.md) (8-phase execution roadmap, invariants, and contracts)
- [AIENOS Technical Specification & Contracts (Phases 3–5)](PHASE_3_TO_5_SPECIFICATION.md) (Agent State ABI, Cortex, AEGIS & Worlds, and C1 CoW Prefix Tree)
- [AIENOS Systems Integration Sequence & Epistemic Calibration](SYSTEMS_INTEGRATION_SEQUENCE.md) (10-step empirical verification sequence and host vs. native qualification)
- [Architectural Decision Records](adr/README.md) (Accepted architectural decisions: [ADR 0001](adr/0001-native-boot-milestone-and-linux-island.md), [ADR 0002](adr/0002-incumbent-os-as-migration-environment.md), [ADR 0003](adr/0003-bootstrap-firmware-handoff-and-minimal-object-store.md), [ADR 0004](adr/0004-reversibility-definition-and-network-effect-boundary.md), [ADR 0005](adr/0005-unified-memory-c1-cow-and-reservation-accounting.md), [ADR 0006](adr/0006-deterministic-recovery-core-and-offline-operator-authority.md))

## 1. What AIENOS is

AIENOS is the operating system. The resident AIEN agent is its primary user interface, coordinator, and policy-aware control plane. Graphical interfaces are projections of agent state that the agent can construct and change on request; there is no fixed desktop.

The model is never the kernel. The kernel is small, deterministic, auditable, and must function with no model loaded. It schedules CPU time, manages memory, services interrupts, mounts storage, enforces capability boundaries, restores a known World, authenticates the operator, recovers networking, kills processes, rolls back updates, and boots into recovery. The kernel operates deterministically without an AI model; recovery is governed by the deterministic Recovery Core ([ADR 0006](adr/0006-deterministic-recovery-core-and-offline-operator-authority.md)).

The agent is the operating interface, not the root of trust:

```text
Hardware / firmware
  -> AIEN boot trust
  -> minimal deterministic AIEN kernel
  -> security + capability primitives
  -> AEGIS
  -> AIEN Runtime
  -> AIEN Agent
```

The agent cannot declare itself authorized. Irreversible actions flow `EffectIntent -> AEGIS -> Effect Broker -> driver`.

## 2. Stack

```text
You
  -> AIEN Agent (persistent self, planner/router, operator UI)
  -> J-Space Worlds | Capability Graph | Cortex Memory
  -> AEGIS (capability grants)
  -> AIEN Runtime (models, tools, skills, fabric, effects, data)
  -> AIEN Kernel (scheduler, memory, IPC/capabilities, drivers, networking, storage)
  -> Hardware
```

- **Applications become capabilities** (for example `mail.send`, `image.edit`, `code.build`). Skills compose capabilities. An app is optional presentation and never owns data.
- **Personal data is OS state:** Person, Conversation, Message, Document, Photo, Video, Project, Repository, CalendarEvent, Device, CredentialRef, Task, World, Memory.
- **Personal Fabric:** a given computer is Machine N, not "the AIEN computer." Hardware and vendor details are capabilities, not identities.
- **Models are replaceable components** behind a Model ABI: locally stored, no cloud or provider account required. The model proposes thought and action; it does not define truth, authority, policy, identity, storage, or the OS.
- **Unified memory and explicit block accounting:** Hardware unified addressability (NVLink-C2C) is managed via explicit block ownership, distinct subsystem memory budgets, and copy-on-write prefix trees ([ADR 0005](adr/0005-unified-memory-c1-cow-and-reservation-accounting.md)).

## 3. Sovereignty and the trusted base

Sovereignty does not mean inventing every component. It means no outside organization is required to boot the machine, access data, authenticate the operator, authorize the agent, compile the trusted core, recover the system, change models, move to different hardware, or keep operating.

The trusted base (boot, kernel, memory management, scheduler, storage core, cryptography, identity, AEGIS, capability enforcement, update verification, recovery, provenance verification) builds from inspectable source with a toolchain that can be independently obtained, preserved, and reproduced. It has no mandatory dependency on a proprietary compiler, runtime, cloud service, licensing server, or opaque build step.

Opaque technology (for example a closed compiler) is allowed only in experiments, accelerator research, benchmark kernels, optional performance modules, and compatibility layers, and only with a fully open fallback. **Opaque software may accelerate AIENOS. It may not become necessary to trust, build, boot, recover, or control AIENOS.**

Accepted exception: silicon that physically requires vendor-signed firmware (for example the GPU's GSP firmware) keeps that firmware.

**Fastest wins, scoped:** for a capability AIENOS natively owns, the fastest correct implementation wins. A compatibility island may outperform the native path for a while, but it does not define the trusted base or the destination ([ADR 0001](adr/0001-native-boot-milestone-and-linux-island.md)).

**Host operating systems:** Windows, macOS, and Linux are bootstrap and migration environments, not the target runtime. **AIENOS may learn from the host, but it must not require the host to survive** ([ADR 0002](adr/0002-incumbent-os-as-migration-environment.md)).

**Persistent storage:** Persistent storage avoids POSIX filesystem complexity in favor of the native AIEN System Store with content-addressed model extents and append-only journals ([ADR 0003](adr/0003-bootstrap-firmware-handoff-and-minimal-object-store.md)).

## 4. Security

- **Boot trust:** Secure Boot off during early development. Before daily use: firmware verifies the operator's key, the operator's key verifies AIENOS boot artifacts, AIENOS verifies kernel and runtime components. An offline recovery key and recovery media are designed before enforcement.
- **Encryption at rest:** conversations, Cortex, projects, World state, credentials, agent memories, model-private data, configuration, caches, and swap-equivalents. Unlock at startup; later hardware sealing plus an operator secret. Credentials receive extra protection after unlock.
- **Identities from day one:** operator, agent identities, system services, remote Machines, future household users; each with separate capabilities, memory visibility, authority, and provenance. No login screens or profiles in version one.

## 5. Agent authority

Free inside reversible state; explicit authorization at irreversible boundaries. Each category is tunable by the operator.

Autonomous by default: read local files, search Cortex, run inference, inspect hardware and system state, run tests and diagnostics, create temporary files and Worlds, make rollback-safe changes inside a reversible World, change ordinary agent preferences.

Operator approval required: permanent deletion, overwriting important data, external email or messages, publishing code, spending money, credential changes, exporting private information, contacting untrusted machines, installing privileged components, boot or security policy changes, changing AEGIS, replacing the kernel, promoting RSI-generated system changes. All outbound network traffic, external device state, and telemetry are external effects requiring AEGIS capability evaluation, even when read-only ([ADR 0004](adr/0004-reversibility-definition-and-network-effect-boundary.md)).

Self-improvement may tune scheduler, allocator, KV, caching, UI, routing, network, kernel implementation, placement, and power policy only out of band, through evaluation, canary, signing, and promotion gates, never by rewriting the running kernel.

## 6. First milestone

Power on, AIENOS boots directly (Linux is not the host), the AIEN agent starts on a local screen and keyboard (plain console), a local model loads, the operator talks to it, and Cortex and state persist across reboot. CPU inference is acceptable. Networking follows immediately after.

The first agent's job is running, understanding, diagnosing, repairing, and improving AIENOS itself. Coding help comes second; general conversation later.

## 7. Roadmap

1. **Linux reference baseline:** freeze the existing Linux/NVIDIA inference stack as a reproducible, tagged reference (merged work, verified inference, correctness and performance evidence, identity manifest, verified recovery). No new Linux-side architecture after this.
2. **Weeks:** AIENOS boots on real Spark hardware with CPU, memory, interrupts, storage, console, and recovery.
3. **Then:** agent, local CPU inference, persistent Cortex.
4. **Months:** AIENOS replaces Linux for normal AIEN operation.
5. **As long as necessary:** full hardware sovereignty, including an independent accelerator path.

Every stage boots and does something real.

Steps 2 and 3 are the primary milestone (native AIENOS boot with CPU inference). A minimal-Linux image booting straight into `aien-init` exists only as Benchmark Config B and the temporary GPU compatibility island, and it is never a prerequisite for the native path.

Configs A (Ubuntu reference), B (minimal-Linux island), and C (native AIENOS) run the same frozen workload and report boot-to-ready, ready-to-model, TTFT, throughput, idle and available memory, jitter, power, and branch cost separately ([ADR 0001](adr/0001-native-boot-milestone-and-linux-island.md)).

Native capability migration order: Runtime, Cortex, AEGIS, World/J-Space, Capability Graph, local inference, storage, networking, operator interface, developer tools, mail, cockpit, others. Nothing is rebuilt merely because it exists today.

## 8. Development discipline

- Kernel work happens first under emulation and automated hardware tests. Bare-metal Spark tests run in scheduled windows.
- Always keep: a known-good AIENOS boot entry, the existing Linux installation, independent recovery media, low-level diagnostics where possible, and rollbackable boot configuration. Crashes are acceptable; destroying the working environment is not.
- Developed in public, labelled experimental. No support or compatibility obligations yet.

## 9. Authority and escalation

The operator sets direction and approves milestones and permanent boundaries. AI operators work autonomously between gates: implement, test, benchmark, record evidence, continue.

Escalate to the operator: root of trust, boot policy, cryptographic identity, irreversible data formats, security boundaries, user authority, permanent hardware assumptions, licensing, externally visible protocol commitments, removing recovery paths, new irreversible agent authority, RSI promotion rules, major architecture changes.

Milestone reports show what was built, what passed, what failed, what changed, the evidence, remaining risks, and the proposed next milestone.

## 10. The persistent thing

The persistent thing is AIEN itself. Hardware is replaceable beneath it. Models, interfaces, tools, and Machines are replaceable around it. If a company disappears tomorrow, the long-term target is that AIENOS continues to boot and remains the operator's.
