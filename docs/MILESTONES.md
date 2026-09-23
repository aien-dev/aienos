# AIENOS Architectural Milestones Matrix & Execution Plan

**Status:** Confirmed Architectural Specification  
**Version:** 1.0.0  
**Governing Documents:**
- `docs/ARCHITECTURE.md` (Governing Architecture)
- `docs/BLUEPRINT.md` (Final Architectural Blueprint, 37 Sections)
- `docs/adr/0001-native-boot-milestone-and-linux-island.md` (ADR 0001)
- `docs/adr/0002-incumbent-os-as-migration-environment.md` (ADR 0002)

> **Foundational Mandate to the Engineering Agent:**  
> *“You own the route; this document owns the destination.”*

---

## 1. Master Phased Execution Framework

The AIENOS master execution sequence progresses across eight distinct phases. The order expresses architectural dependency, not administrative bureaucracy. Each phase establishes sovereign deliverables, enforceable invariants, objective acceptance tests, and explicit escalation triggers.

```text
PHASE 1: Freeze Reality (Config A Ubuntu Reference Baseline)
   ↓
PHASE 2: Native AIENOS Boot (Minimal Bare-Metal Substrate)
   ↓
PHASE 3: The Agent Wakes Up (Persistent Agent & Early Memory)
   ↓
PHASE 4: Native System Intelligence (Capability Graph & AEGIS)
   ↓
PHASE 5: Native Hardware Acceleration (Sovereignty & A/B/C Competition)
   ↓
PHASE 6: Migration System (Machine Capsule & Reversible Install)
   ↓
PHASE 7: Multi-Hardware AIENOS (BSP Expansion Beyond DGX Spark)
   ↓
PHASE 8: Personal Fabric (Distributed Nodes & State Mobility)
   ↓
MATURE AIENOS: Sovereign Agent-Native Personal Computing
```

---

## 2. Core Architectural Invariants Governing All Phases

Every implementation artifact must preserve these ten foundational invariants:

1. **Model is Never the Kernel (Blueprint §6, ARCHITECTURE.md §1):** Kernel schedules CPU, manages memory, services interrupts, mounts storage, and authenticates the operator with zero AI models loaded.
2. **Separation of Authority and Proposal (Blueprint §5, ARCHITECTURE.md §1):** The agent cannot authorize itself. Irreversible actions strictly flow: `Model Proposal -> EffectIntent -> AEGIS Policy -> Effect Broker -> Driver`.
3. **Identity vs. Execution Separation (Blueprint §2):** Losing physical inference state (GPU crash, bus reset, KV cache eviction, process restart) costs computation, never logical identity.
4. **Sovereign Trusted Base (Blueprint §4, ARCHITECTURE.md §3):** Boot, kernel, memory management, scheduler, storage core, cryptography, and AEGIS build from inspectable open-source code with zero mandatory proprietary or cloud dependencies.
5. **Compatibility as Island, Not Foundation (Blueprint §8, ADR 0001):** Compatibility layers (e.g. minimal Linux GPU island / Config B) are temporary acceleration mechanisms. Removing them must leave native AIENOS fully buildable, bootable, and recoverable.
6. **Reversible Autonomy (Blueprint §12, ARCHITECTURE.md §5):** Agent is fully autonomous inside reversible Worlds; explicit operator cryptographic approval is required at irreversible boundaries.
7. **Capability-Centric Computing (Blueprint §13, ARCHITECTURE.md §2):** Functionality is organized into composable capabilities (`filesystem.read`, `mail.send`, `code.build`). Applications do not own underlying capabilities or personal data; personal data is native OS state.
8. **Replaceable Model Intelligence (Blueprint §14):** The Model ABI decouples weights, tokenizers, backends, and sampling from agent identity. Changing models does not redefine agent identity.
9. **Constrained "Fastest Wins" (Blueprint §31, ADR 0001):** Among implementations satisfying correctness, security, sovereignty, and interface contracts, the fastest measured implementation wins. Speed never overrides sovereignty.
10. **Controlled Self-Improvement (Blueprint §32, ARCHITECTURE.md §5):** Recursive self-improvement occurs strictly out-of-band in isolated Worlds via candidate evaluation, signing, and canary deployment; the agent never mutates the running kernel in-place.

---

## 3. Autonomous Engineering Protocol & Escalation Triggers

Engineering agents operate autonomously within milestone boundaries (Blueprint §4, §29, §30):
- **Autonomous Authority:** Agents freely select data structures, crate layouts, memory allocators, scheduling algorithms, low-level assembly routines, build scripts, and optimization passes.
- **Goal Immutability:** If an implementation approach fails, the agent iterates or replaces the implementation (Blueprint §30); the destination milestone and architectural invariants remain fixed.
- **The 10 Mandatory Escalation Triggers (Requiring Immediate Operator Signoff):**
  1. Alteration of the root of trust, Secure Boot policy, or cryptographic boot verification chain.
  2. Broadening of operator authority, removal of AEGIS policy gates, or bypass of the Effect Broker.
  3. Modification of persistent identity semantics or the Agent State ABI hierarchy.
  4. Weakening of security boundaries, memory isolation, or J-Space World containment.
  5. Introduction of irreversible data formats into Cortex or persistent storage.
  6. Permitting compatibility infrastructure (e.g. Linux or proprietary CUDA) to become a mandatory prerequisite for native AIENOS build, boot, or recovery.
  7. Introducing closed-source proprietary binaries, external cloud licensing, or opaque compiler toolchains into the trusted base.
  8. Removing or disabling recovery media, fallback boot targets, or system rollback guarantees.
  9. Alteration of externally visible protocol commitments or API contracts.
  10. Structural modifications to the 7-layer architecture stack.

---

## 4. Detailed Phase Specifications

### Phase 1: Freeze Reality (Config A Reference Baseline)
- **Blueprint Sections Mapped:** §15 (Phase 1 Freeze reality), §21 (Machine Capsule), §27 (Evidence Architecture).
- **Secondary Sections:** §1 (Vision), §4 (Engineering Boundaries), §36 (Execution Sequence).
- **Governing ADRs:** [ADR 0001](adr/0001-native-boot-milestone-and-linux-island.md) (defines Config A as the frozen Ubuntu reference baseline), [ADR 0002](adr/0002-incumbent-os-as-migration-environment.md) (host inspection generates Machine Capsule without host runtime dependencies).
- **Mission:** Freeze the operational DGX Spark / Linux reference baseline (`Config A`) before writing native code, establishing an auditable, reproducible ground truth for all performance and sovereignty claims.
- **Deliverables & Artifacts:**
  - `scripts/freeze_reality.sh`: Non-destructive host inspection script capturing hardware identity, firmware, kernel parameters, runtime libraries, and workspace commit digests.
  - `evidence/config_a_reference_bundle.json`: Verifiable reference bundle containing the complete 15-component Section 21 Machine Capsule.
  - `schemas/machine_capsule.schema.json`: Formal JSON schema enforcing Section 21 specification.
  - `scripts/verify_evidence.sh`: Automated schema and cryptographic SHA-256 validation script.
- **Architectural Invariants:**
  - Non-destructive execution: zero writes outside `evidence/`; no modifications to host disks, boot entries, NVRAM, or EFI partitions.
  - 100% empirical truth: no hardware descriptors may be mocked, synthesized, or assumed.
  - Self-contained verifiability: verifiable with standard open-source tools (`jq`, `sha256sum`).
- **Acceptance Criteria:**
  - `bash scripts/freeze_reality.sh` exits with return code `0`.
  - `evidence/config_a_reference_bundle.json` exists, is valid JSON, and contains non-empty sections for all 15 Machine Capsule components.
  - `bash scripts/verify_evidence.sh evidence/config_a_reference_bundle.json` exits with return code `0`, confirming schema validity and SHA-256 self-consistency.
- **Escalation Triggers:**
  - Hardware inspection requiring destructive host actions or privileged modifications.
  - Missing critical hardware descriptors in sysfs/DMI preventing Section 21 compliance.

---

### Phase 2: Native AIENOS Boot (Minimal Bare-Metal Substrate)
- **Blueprint Sections Mapped:** §6 (The AIENOS Kernel), §16 (Phase 2 Native AIENOS boot).
- **Secondary Sections:** §4 (Sovereignty Boundaries), §5 (Boot & Trust Substrate), §7 (Hardware Ownership), §27 (Evidence Architecture).
- **Governing ADR:** [ADR 0001](adr/0001-native-boot-milestone-and-linux-island.md) (mandates native AIENOS boot on bare-metal ARM64 as primary milestone; minimal Linux wrappers prohibited as native substrate).
- **Mission:** Power on the DGX Spark and boot the sovereign `no_std` AIENOS kernel targeting 64-bit ARM (`aarch64`) directly on bare metal without Linux hosting the system.
- **Deliverables & Artifacts:**
  - `crates/aienos-kernel/Cargo.toml`: Standalone `no_std`, `no_main` bare-metal kernel crate targeting `aarch64-unknown-none`.
  - `crates/aienos-kernel/linker.ld`: Sovereign ARM64 linker script enforcing clean segment separation (`.text`, `.rodata`, `.data`, `.bss`, `.stack`) and deterministic entry point `_start`.
  - `crates/aienos-kernel/src/main.rs`: Bare-metal CPU initialization, early stack setup, and boot flow.
  - `crates/aienos-kernel/src/drivers/uart.rs`: MMIO serial console driver targeting the physical Tegra/16550 UART at MMIO base `0x16A00000` (stride 4, 32-bit width, 921600 baud).
  - `crates/aienos-kernel/src/panic.rs`: Sovereign panic handler emitting deterministic telemetry to UART and executing an infinite `wfi` halt loop.
  - `scripts/verify_all.sh`: End-to-end verification script compiling the kernel and verifying evidence.
  - `evidence/build_and_test_evidence.log`: Verifiable compilation and test execution log.
- **Architectural Invariants:**
  - Model is Never the Kernel (Blueprint §6): Boot, memory initialization, interrupt setup, and panic handling proceed with zero AI models loaded.
  - Sovereign Toolchain (Blueprint §4): Zero dependencies on Linux standard library (`std`), glibc, musl, or Linux syscalls.
  - Deterministic Panic: Panic handler must disable interrupts (`daifset`) and halt CPU without external runtime shims.
- **Acceptance Criteria:**
  - `cargo check --target aarch64-unknown-none` within `crates/aienos-kernel` exits with status `0` and zero warnings.
  - `cargo build --target aarch64-unknown-none --release` produces valid bare-metal ELF binary.
  - Linker layout inspection verifies that `_start` is at the expected entry address and segments do not overlap.
  - Serial driver writes ASCII telemetry to MMIO register base `0x16A00000`.
- **Escalation Triggers:**
  - Any compilation requirement introducing dependencies on Linux libc, POSIX headers, or host kernel modules.
  - Firmware incompatibility requiring proprietary binary shims to achieve early CPU control.
  - Modification of the physical host EFI system partition (`/boot/efi`) without prior operator authorization.

---

### Phase 3: The Agent Wakes Up (Persistent Agent & Early Memory)
- **Blueprint Sections Mapped:** §2 (Central Architectural Principle), §11 (Cortex), §14 (Model ABI), §17 (Phase 3 The agent wakes up).
- **Secondary Sections:** §5 (Boot Trust), §9 (Agent State ABI), §33 (UX Feel).
- **Mission:** Initialize the AIEN Neural Runtime on the native kernel, load a local CPU inference model, wake the persistent resident AIEN agent, and verify that Cortex persists epistemic memory across reboots.
- **Deliverables & Artifacts:**
  - `crates/aienos-runtime/`: Native neural runtime executive operating directly on kernel substrate.
  - `crates/aienos-model-abi/`: Model ABI implementation abstracting weights, tokenizers, and execution backends from agent identity.
  - `crates/aienos-cortex/`: Early durable Cortex storage engine supporting write-ahead epistemic logging on NVMe storage.
  - Local CPU inference backend executing quantized language model (e.g. Llama-3.2-1B / Qwen).
  - Native console dialogue interface enabling direct operator-agent interaction.
  - `evidence/phase3_reboot_persistence_receipt.json`: Verifiable proof of state retention across soft reboot.
- **Architectural Invariants:**
  - Identity vs Execution Separation (Blueprint §2): Restarting the model, clearing KV cache, or rebooting the machine must not create a new agent identity.
  - Self-Diagnostic Focus (Blueprint §17): The first agent's primary duty is observing, diagnosing, and repairing AIENOS itself; general conversational features are secondary.
  - Model Replaceability (Blueprint §14): Changing model weights or backend leaves agent identity and Cortex history intact.
- **Acceptance Criteria:**
  - Machine boots natively -> Runtime starts -> Local model weights load into RAM -> Agent prompts operator on console within 10 seconds.
  - Operator issues diagnostic command via console; agent queries kernel tables and returns factual response.
  - System executes reboot; agent wakes, loads previous session context from Cortex, and acknowledges continuity.
- **Escalation Triggers:**
  - Failure of agent identity continuity across system reboot.
  - Model weights or runtime demanding network connection or cloud licensing servers to execute.
  - Memory corruption during CPU weight ingestion that forces fallback to Linux userspace.

---

### Phase 4: Native System Intelligence (Capability Graph & System Control)
- **Blueprint Sections Mapped:** §3 (Final System Architecture), §5 (Boot & Trust / AEGIS), §9 (Agent State ABI), §10 (Copy-on-Write Prefix Sharing), §12 (Worlds / J-Space), §13 (Capability Graph), §18 (Phase 4 Native system intelligence), §28 (C1 Invariant Foundation), §32 (Self-Improvement).
- **Secondary Sections:** §11 (Cortex Deep Tiering), §35 (Strategic Endpoint).
- **Mission:** Transform the resident agent into the primary system interface and coordinator via dynamic Capability Graph composition. Enforce AEGIS policy control and J-Space reversible execution Worlds. Formalize the Agent State ABI and C1 Copy-on-Write prefix sharing.
- **Deliverables & Artifacts:**
  - `crates/aienos-aegis/`: AEGIS capability authorization engine enforcing deterministic security policies.
  - `crates/aienos-broker/`: Effect Broker translating validated `EffectIntent` into concrete device/storage/network actions.
  - `crates/aienos-capabilities/`: Capability Graph registry managing dynamic capability composition.
  - `crates/aienos-jspace/`: Reversible World sandbox subsystem with snapshotting, checkpointing, and instant rollback.
  - `crates/aienos-state/`: Agent State ABI managing `LogicalAgentId`, `LogicalBranchId`, and physical `SequenceId`.
  - `crates/aienos-c1/`: C1 verification suite proving branch isolation, memory conservation, and parent survival.
- **Architectural Invariants:**
  - Agent Cannot Authorize Itself (Blueprint §5): Every irreversible system action flows `EffectIntent -> AEGIS -> Effect Broker`.
  - Reversible Autonomy (Blueprint §12): Total freedom inside reversible Worlds; strict cryptographic approval at irreversible boundaries.
  - Mathematical Branch Isolation (Blueprint §28): Reasoning branches share physical prefix pages; child branch memory corruption can never leak into parent state.
- **Acceptance Criteria:**
  - Agent processes natural language operator intent ("find memory leak") by generating an isolated World, running diagnostics, and proposing a safe resolution diff.
  - AEGIS policy interceptor denies an unauthorized `EffectIntent` (e.g. disk write to reserved partition) with an auditable cryptographic receipt.
  - C1 benchmark runs 100 concurrent reasoning branches sharing a 100K token prefix; memory consumption scales sub-linearly with zero state cross-contamination.
  - Failed build experiment inside a World rolls back cleanly with zero modified bytes on the root filesystem.
- **Escalation Triggers:**
  - Any architectural bypass where an agent executes an external effect without passing through AEGIS.
  - Silent broadening of operator permissions or capability grant escalation.
  - State leak across reasoning branches violating the C1 invariant.

---

### Phase 5: Native Hardware Acceleration (GPU/NVLink Ownership & A/B/C Competition)
- **Blueprint Sections Mapped:** §7 (Hardware Sovereignty), §8 (Compatibility Islands), §19 (Phase 5 Native hardware acceleration), §31 ("Fastest Wins" Properly Defined).
- **Secondary Sections:** §10 (CoW Prefix Sharing), §27 (Evidence Architecture).
- **Governing ADR:** [ADR 0001](adr/0001-native-boot-milestone-and-linux-island.md) (defines 3-way configuration competition Config A vs B vs C; Config B must never become prerequisite for Config C; defines 9-11 benchmark metrics and scoped 'fastest wins').
- **Mission:** Progressively transition hot hardware paths (accelerator, NVLink-C2C, NVMe storage, network) to native AIENOS ownership. Execute the standardized A/B/C benchmark competition across Config A (Ubuntu baseline), Config B (Minimal Linux compatibility island), and Config C (Native AIENOS bare-metal substrate) measuring 11 empirical metrics.
- **Deliverables & Artifacts:**
  - `crates/aienos-accel/`: Native GPU/NPU memory management and execution driver for NVIDIA Blackwell GB10 over NVLink-C2C.
  - `crates/aienos-nvme/`: Direct high-performance NVMe driver bypassing general-purpose VFS layers.
  - `crates/aienos-net/`: Native network driver (Realtek RTL8127 2.5GbE).
  - `scripts/benchmark_abc.sh`: Non-interactive benchmark suite executing identical prompt/model envelopes across Configs A, B, and C.
  - `evidence/benchmark_abc_receipt.json`: Standardized 11-metric evaluation receipt documenting comparative performance.
- **Architectural Invariants:**
  - Sovereignty Precedes Speed (Blueprint §31, ADR 0001): "Fastest wins" applies ONLY among implementations satisfying correctness, security, and sovereignty contracts.
  - Compatibility Island Isolation (Blueprint §8, ADR 0001): Config B is a temporary control experiment and Era II island; removing it must leave Config C fully operational.
  - Zero Closed Blobs in Trusted Base: Native accelerator interfaces must not introduce proprietary, uninspected userspace binaries into the core kernel address space.
- **Acceptance Criteria:**
  - Standardized benchmark executes across Config A, Config B, and Config C measuring:
    1. Cold boot to agent ready (ms)
    2. Agent ready to model ready (ms)
    3. TTFT (Time to First Token, ms)
    4. Steady-state throughput (tokens/s)
    5. Idle physical memory footprint (MB)
    6. Available workload memory (MB)
    7. Scheduler jitter (µs)
    8. Power consumption (W)
    9. Branch creation latency (µs)
    10. Branch physical memory cost (KB)
    11. State restore time (ms)
  - Config C demonstrates measurable latency, jitter, or memory density improvements over Config A while maintaining 100% test pass rates.
- **Escalation Triggers:**
  - Proposal to declare Config B (Linux island) as the permanent architecture.
  - Introduction of proprietary closed runtime blobs that cannot be isolated into an optional island.
  - Benchmark regression where native paths fail correctness or safety requirements in pursuit of throughput.

---

### Phase 6: Migration System (Machine Capsule, Dual-Boot & Reversible Install)
- **Blueprint Sections Mapped:** §20 (Phase 6 Migration system), §21 (Machine Capsule), §22 (Reversible installation), §23 (Progressive escape from incumbent OS), §34 (The adoption proposition), ADR 0002.
- **Secondary Sections:** §4 (Sovereignty Boundaries), §5 (Boot Trust).
- **Governing ADR:** [ADR 0002](adr/0002-incumbent-os-as-migration-environment.md) (governs progressive escape from incumbent OS; AIENOS may learn from host but must not require host to survive).
- **Mission:** Deploy host-side bootstrap tools on incumbent operating systems (Windows, macOS, Linux). Scaffolding inventories the machine, generates a Section 21 Machine Capsule, installs AIENOS with reversible dual-boot, and guides the operator through the 7-stage progressive escape lifecycle.
- **Deliverables & Artifacts:**
  - `tools/aienos-installer/`: Host-side inspection and partition setup CLI.
  - Machine Capsule compiler validating host hardware against AIENOS BSP requirements.
  - Reversible EFI dual-boot installer configuring side-by-side boot entries without overwriting host bootloaders.
  - Automated watchdog recovery harness reverting to the incumbent OS if native boot fails.
  - Adoption lifecycle tracker managing progression across Stages 1 through 7.
- **Architectural Invariants:**
  - Host as Scaffolding (Blueprint §20, ADR 0002): AIENOS may learn from the host, but must never require the host to survive once installed.
  - Reversible Installation (Blueprint §22): The incumbent OS bootloader, partition table, and user data remain intact and bootable at all times.
  - Non-Coercive Migration (Blueprint §23): AIENOS never forces host removal; the operator retains full sovereignty over migration stages.
- **Acceptance Criteria:**
  - Installer runs non-destructively on host OS; outputs valid Section 21 Machine Capsule.
  - Dual-boot partition carved and formatted; EFI boot entry registered with watchdog counter.
  - Test boot into AIENOS verifies kernel, storage, input, and model loading.
  - Simulated kernel panic during boot triggers watchdog reset into incumbent OS bootloader.
- **Escalation Triggers:**
  - Incompatible host disk layout (e.g. unsupported software RAID or locked bootloader) that cannot be safely partitioned.
  - Host inspection identifying proprietary peripherals lacking open documentation or safe compatibility fallback.
  - Accidental modification or corruption of host OS partitions.

---

### Phase 7: Multi-Hardware AIENOS (BSP Expansion Beyond DGX Spark)
- **Blueprint Sections Mapped:** §7 (Hardware Sovereignty), §21 (Machine Capsule), §24 (Phase 7 Multi-hardware AIENOS).
- **Secondary Sections:** §2 (Identity Separation), §14 (Model ABI).
- **Mission:** Decouple AIENOS from DGX Spark hardware assumptions. Generalize kernel and runtime abstractions into a formal Hardware Abstraction Layer (HAL) and Board Support Packages (BSPs) for desktop x86_64, generic ARM64, AMD accelerators, and Apple silicon.
- **Deliverables & Artifacts:**
  - `crates/aienos-hal/`: Hardware Abstraction Layer defining standard CPU, MMU, interrupt, timer, and DMA interfaces.
  - `crates/bsp-dgx-spark/`: Reference BSP for NVIDIA Grace Blackwell P4242 board.
  - `crates/bsp-x86_64/`: Standard PC / ACPI Board Support Package.
  - `crates/bsp-arm64-generic/`: Generic ARM64 Board Support Package.
  - Cross-architecture automated emulation test harness (QEMU x86_64 and QEMU aarch64).
  - Platform portability receipts (`evidence/platform_matrix_receipt.json`).
- **Architectural Invariants:**
  - Hardware Independence (Blueprint §24): Spark is a reference machine, not AIEN's identity. Core kernel logic, AEGIS, Cortex, and Agent State ABI are strictly platform-agnostic.
  - Uniform Contract Enforcement: All supported platforms must guarantee identical behavioral semantics for capability execution, branch isolation, and memory persistence.
- **Acceptance Criteria:**
  - `cargo test --workspace` passes across both `aarch64` and `x86_64` targets.
  - Automated QEMU test boots AIENOS on both `x86_64` and `aarch64`, initializing serial consoles, memory maps, and panic handlers.
  - Agent state exported from DGX Spark loads and resumes execution on an x86_64 target under identical invariant proofs.
- **Escalation Triggers:**
  - Platform-specific workarounds that leak architecture-dependent behavior into higher-level runtime or agent crates.
  - Introduction of proprietary binary firmware blobs into the core HAL without open-source fallbacks.

---

### Phase 8: Personal Fabric (Distributed Nodes & State Mobility)
- **Blueprint Sections Mapped:** §1 (The Final Vision), §25 (Phase 8 Personal Fabric), §26 (State Mobility), §33 (What the Finished System Feels Like), §35 (The Strategic Endpoint), §37 (Final Definition of Success).
- **Secondary Sections:** §2 (Central Principle), §9 (Agent State ABI), §27 (Evidence Architecture).
- **Mission:** Expand AIEN into a personal distributed fabric where a single logical AIEN identity spans multiple physical machines (DGX Spark compute + laptop display/keyboard + mobile sensors). Implement state mobility (`migrate(agent_state)`) allowing execution branches to move across physical nodes with dynamic KV reconstruction. Fully satisfy all 15 Blueprint Section 37 final success criteria.
- **Deliverables & Artifacts:**
  - `crates/aienos-fabric/`: Sovereign peer-to-peer fabric protocol for inter-node capability discovery, state synchronization, and RPC.
  - State Mobility Engine: Native implementation of `migrate(agent_state)` with on-demand physical KV reconstruction.
  - Heterogeneous compute scheduler placing model inference on accelerator nodes and UI projection on client devices.
  - Autonomous local fallback daemon ensuring disconnected nodes remain functional.
  - Blueprint Section 37 Master Verification Suite (`tests/section_37_audit.rs`).
  - `evidence/phase8_final_success_receipt.json`: Signed verification receipt certifying full realization of the AIENOS vision.
- **Architectural Invariants:**
  - Identity Above Machines (Blueprint §25): The agent's identity exists above physical machines; computers are replaceable compute and I/O resources.
  - State Mobility Invariant (Blueprint §26): Logical state migrates; physical state is reconstructed or lazily synchronized; migration preserves continuous identity.
  - Partition Sovereignty: Node disconnection must never freeze local core operating capabilities; nodes fall back to autonomous local mode.
- **Acceptance Criteria:**
  - Two independent physical nodes establish encrypted P2P fabric connection and merge capability graphs.
  - Active reasoning branch is suspended on Node A, transmitted across the fabric, and resumed on Node B with identical context within 2000 ms.
  - Section 37 Master Audit passes 100% of all 15 final criteria.
- **Escalation Triggers:**
  - Network protocol introducing centralized cloud coordination or external third-party identity providers.
  - Split-brain network partition resulting in permanent divergent agent identities without automatic reconciliation.

---

## 5. Master 37-Section Blueprint Traceability Matrix

| # | Section Title | Primary Phase | Key Deliverables | Enforced Invariants | Verification Gate |
|---|---|---|---|---|---|
| **1** | The final vision | Phase 8 | `docs/MILESTONES.md`, Boot flow | Identity survives hardware/model changes | Direct power-on boot into AIEN |
| **2** | Central architectural principle | Phase 3 | `crates/aienos-state/`, Cortex | State loss costs compute, not identity | Identity persists across soft reboot |
| **3** | Final system architecture | Phase 4 | 7-layer stack in `crates/` | Strict layer boundary separation | End-to-end intent execution crossing layers |
| **4** | Fixed vs decision space | Phase 2 | Cargo workspace, sovereign crates | Zero cloud or proprietary dependencies | Builds with open toolchains |
| **5** | Boot and trust architecture | Phase 2 | Secure Boot hooks, AEGIS engine | Agent cannot authorize itself | Unauthorized intent rejected |
| **6** | The AIENOS kernel | Phase 2 | `aienos-kernel`, `linker.ld` | Model is never the kernel | Boots without model loaded |
| **7** | Hardware sovereignty | Phase 5 | `crates/aienos-accel/`, NVMe | Direct hot-path hardware ownership | Native MMIO/DMA without host OS |
| **8** | Compatibility islands | Phase 5 | Config B (`minimal-linux-island`) | Island is not the foundation | Boots with Config B deleted |
| **9** | Agent State ABI | Phase 4 | `crates/aienos-state/` | Logical state decoupled from physical KV | Branch fork/suspend/resume unit tests |
| **10** | Copy-on-write agent computation | Phase 4 | `crates/aienos-c1/`, CoW allocator | Read-only prefix KV page sharing | Sub-linear memory scaling across branches |
| **11** | Cortex | Phase 3 | `crates/aienos-cortex/`, NVMe log | Epistemic distinctions preserved | Cortex persistence survives reboot |
| **12** | Worlds / J-Space | Phase 4 | `crates/aienos-jspace/`, Worlds | Reversible inside; approval at boundary | Rollback discards diff with zero leak |
| **13** | Capability Graph | Phase 4 | `crates/aienos-capabilities/` | Capabilities replace applications | Intent executes via capability composition |
| **14** | Model ABI | Phase 3 | `crates/aienos-model-abi/` | Models are replaceable components | Model swap leaves identity intact |
| **15** | Phase 1 — Freeze reality | Phase 1 | `freeze_reality.sh`, bundle JSON | Non-destructive read-only capture | Script exits 0; schema validates |
| **16** | Phase 2 — Native AIENOS boot | Phase 2 | `aienos-kernel`, UART driver | Boots bare metal without Linux host | Cargo build exits 0; emits banner |
| **17** | Phase 3 — The agent wakes up | Phase 3 | Runtime, CPU model, console loop | Agent wakes natively; Cortex persists | Console dialogue; persists post-reboot |
| **18** | Phase 4 — Native intelligence | Phase 4 | AEGIS, Broker, Capabilities, Worlds | Natural language operating control | Intent diagnostics pass in sandbox |
| **19** | Phase 5 — Hardware acceleration | Phase 5 | Native GB10 driver, benchmark suite | Constrained "fastest wins" | 11-metric benchmark report emitted |
| **20** | Phase 6 — Migration system | Phase 6 | `tools/aienos-installer/` | Host OS is scaffolding | Dual-boot installed from host OS |
| **21** | Machine Capsule | Phase 1 | Machine Capsule schema & parser | 15-component hardware descriptor | Schema validation passes on bundle |
| **22** | Reversible installation | Phase 6 | Dual-boot partitioner, watchdog | Host OS remains bootable | Watchdog resets to host on panic |
| **23** | Progressive escape from host | Phase 6 | 7-stage migration state machine | Voluntary adoption progression | Progression across Stages 1–7 verified |
| **24** | Phase 7 — Multi-hardware | Phase 7 | `aienos-hal`, x86_64/ARM64 BSPs | Hardware is replaceable substrate | Tests pass on both x86_64 and aarch64 |
| **25** | Phase 8 — Personal Fabric | Phase 8 | `crates/aienos-fabric/`, P2P sync | Single identity across machines | P2P capability mesh links nodes |
| **26** | Eventually: state mobility | Phase 8 | `migrate(agent_state)` engine | State moves; physical KV recomputed | Reasoning branch migrates Node A to B |
| **27** | Evidence architecture | Phase 1 | Verification scripts, SHA receipts | Evidence earns claims | Cryptographically signed receipts |
| **28** | C1's role | Phase 4 | `crates/aienos-c1/` formal suite | Proof of branch isolation & CoW | Formal C1 stress tests pass |
| **29** | Autonomous engineering model | Phase 1–8 | Dispatch logs, `progress.md` | Autonomous between milestone gates | Iterations pass without micromanagement |
| **30** | Failure changes route not goal | Phase 1–8 | Engineering logs, alternative algos | Destination milestone is immutable | Alternate algorithm passes gate |
| **31** | "Fastest wins" properly defined | Phase 5 | Benchmark selection filter | Correctness & sovereignty first | Faster candidate rejected if unsovereign |
| **32** | Self-improvement | Phase 4 | World canary evaluation pipeline | Out-of-band evaluation; no live patch | Canary test rejects flawed patch |
| **33** | Finished system feel | Phase 8 | Dynamic UI projection engine | Power on → AIEN wakes | Cold boot wakes interactive agent |
| **34** | The adoption proposition | Phase 6 | Host discovery onboarding flow | Non-coercive adoption | Native boot target prepared safely |
| **35** | The strategic endpoint | Phase 8 | Complete architectural runtime | Operator → Agent → Capabilities → AIENOS | Total agent-native computing realized |
| **36** | Master execution sequence | Phase 1–8 | Milestone dependency DAG | Phased dependency ordering | Exit criteria verified before unlock |
| **37** | Final definition of success | Phase 8 | Master Audit Suite | All 15 criteria verified true | 15/15 binary conditions passing |

---

## 6. Master Success Criteria (Blueprint Section 37) Verification Matrix

| # | Blueprint Section 37 Success Condition | Verifying Phase | Implementing Artifact / Crate | Objective Verification Test Method |
|---|---|---|---|---|
| **1** | The machine can boot without Windows, macOS or Linux acting as its host. | Phase 2 | `crates/aienos-kernel` (`_start`) | Power-on boot test into native bare-metal ELF on DGX Spark; kernel emits UART banner. |
| **2** | AIENOS can recover without an AI model. | Phase 2 | `crates/aienos-kernel` (`recovery.rs`) | Boot into recovery mode with zero model files on storage; mount storage and execute diagnostic shell. |
| **3** | The AIEN agent survives reboot as the same logical entity. | Phase 3 | `crates/aienos-runtime`, `cortex` | Soft reboot during active conversation; agent wakes and verifies prior interaction history. |
| **4** | Cortex survives and preserves evidence/provenance semantics. | Phase 3 | `crates/aienos-cortex` | Write epistemic graph with observations and facts; power cycle; query Cortex and verify hashes. |
| **5** | The model can be replaced without replacing AIEN. | Phase 3 | `crates/aienos-model-abi` | Swap underlying model weights from Model A to Model B; verify agent identity and history remain intact. |
| **6** | Agent inference state can be branched, suspended, reclaimed and reconstructed without changing logical identity. | Phase 4 | `crates/aienos-state`, `crates/aienos-c1` | Create 5 reasoning branches; suspend 3; evict physical KV; resume; verify identity and recomputed context. |
| **7** | The agent operates the machine through explicit capabilities. | Phase 4 | `crates/aienos-capabilities` | Natural language intent translated into `CapabilityCall` (`fs.read`, `system.inspect`) without app silos. |
| **8** | Irreversible effects cross enforceable authorization boundaries. | Phase 4 | `crates/aienos-aegis`, `broker` | Attempt disk partition format; verify AEGIS blocks execution pending operator cryptographic grant. |
| **9** | The operator can recover from AIEN failure. | Phase 3 | Kernel fallback console & recovery media | Kill runtime process; kernel falls back to deterministic low-level recovery console. |
| **10** | No outside company is required for ordinary continued operation. | Phase 2 | Sovereign build chain & local model | Disconnect physical network cable; execute complete boot, inference, storage, and agent loop. |
| **11** | Important native hardware paths are directly controlled by AIENOS. | Phase 5 | `crates/aienos-accel`, `nvme`, `net` | Direct MMIO register access to GB10 accelerator and NVMe block devices without host drivers. |
| **12** | Compatibility layers are optional rather than foundational. | Phase 5 | Benchmark Config B isolation | Delete Config B Linux compatibility image; confirm native AIENOS boots, executes, and recovers. |
| **13** | The system can prove its important performance and correctness claims. | Phase 1 | `scripts/verify_evidence.sh` | Every benchmark and test emits cryptographically signed JSON evidence receipts into `evidence/`. |
| **14** | The user can move to another supported machine without their AIEN being permanently tied to old hardware. | Phase 7 | `crates/aienos-fabric`, `aienos-hal` | Export agent state from DGX Spark; import and resume on x86_64 host under identical identity. |
| **15** | Ordinary experience: Power on the machine. AIEN wakes up. | Phase 8 | Complete integrated AIENOS | Cold power button press leads directly to interactive AIEN agent greeting without intermediate desktop. |
