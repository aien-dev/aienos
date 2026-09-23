# AIENOS Systems Integration Sequence & Epistemic Calibration

> **Status:** Governing Integration Framework
> **Authority:** Operator Directive (2026-09-23)
> **Amendment:** [Continuous-Existence Amendment](CONTINUOUS_EXISTENCE_AMENDMENT.md) ([ADR 0007](adr/0007-continuous-existence-provisioning-once.md)) — binding on all gate acceptance criteria; **gate order unchanged**
> **Stage Transition:** Architecture-Definition → Systems-Integration
> **Core Mandate:** *“You own the route; this document owns the destination.”*

---

## 1. Epistemic Calibration & Precision of Claims

To preserve intellectual integrity across all public documentation, benchmark claims, and engineering reports, the following strict distinctions are enforced:

1. **Host-Tested vs. Native-Qualified**:
   - The modular crates (`aienos-kernel`, `aienos-agent-state`, `aienos-cortex`, `aienos-aegis`, `aienos-c1-tree`) currently have **phase-targeted crates implemented and host-tested**.
   - Host unit tests (`cargo test`) demonstrate component logic on Linux userspace; they **do not** claim that those phases are completed on bare metal.
   - Phases 1 through 8 are marked complete only when their invariants survive execution under real AIENOS boot, hardware resets, and native storage on the DGX Spark.

2. **Prefix Sharing Claims**:
   - “Zero-memory prefix sharing” specifically means **zero duplicated physical KV tensor payload** for the shared token prefix.
   - It does not mean zero bytes allocated anywhere: branch metadata, block tables, reference counters, logical branch IDs, and scheduler bookkeeping consume structured RAM.

3. **Identity Survival Claims**:
   - “Logical identity survives indefinitely” is an **architectural invariant and contract**, not an empirical claim, until crash/reboot/storage-corruption test harnesses actually verify it across the full native stack.
   - Per the [Continuous-Existence Amendment](CONTINUOUS_EXISTENCE_AMENDMENT.md): AIEN is provisioned once; boot, reboot, sleep, model reload, kernel restart, hardware failure, and migration are execution-state transitions—not agent creation events. Empirical claims still require the gate proofs below.

4. **Provisioning vs. Boot**:
   - Only initial provisioning may create a durable `LogicalAgentId`.
   - Normal boot locates, verifies, and resumes an existing identity, or stops in the Recovery Core. It never silently mints a replacement.

---

## 2. The 10-Step Systems Integration Sequence

The engineering question is no longer *“What should AIENOS be?”*
It is: *“Can these independently correct pieces survive contact with one another, real firmware, real storage, real resets, and real hardware while preserving the frozen invariants?”*

```text
Config A Freeze (Linux / DGX Spark reference baseline)
   │
   ▼
Native Boot Spine (firmware -> AIENOS boot artifact -> CPU/mem/UART/halt)
   │
   ▼
aienos-kernel Native Integration (physical MMIO, frame allocator, spinlocks)
   │
   ▼
Native Storage Bring-up (ADR 0003: minimal object store, WAL + model extents)
   │
   ▼
Recovery Core Verification (ADR 0006: deliberate failure, offline auth, no model)
   │
   ▼
Agent State + Cortex Integration (Real Phase 3: persistent identity across reboot)
   │
   ▼
Inference Bring-up (Local CPU GGUF inference, operator dialogue)
   │
   ▼
AEGIS & J-Space Worlds Integration (fail-closed network, standing capabilities)
   │
   ▼
C1 Physical Tree Integration (actual KV state, partial-block forks, reservations)
   │
   ▼
Native Hardware Acceleration (Direct GB10 MMIO, Config B/C 3-way benchmarking)
```

### Detailed Sequence & Acceptance Gates

Continuous-existence clauses below come from the [Continuous-Existence Amendment](CONTINUOUS_EXISTENCE_AMENDMENT.md) and are binding without reordering gates.

#### Step 1: Finish Config A Freeze
Capture the working Linux/NVIDIA reference baseline on the DGX Spark into `evidence/config_a_reference_bundle.json` with cryptographic digests (SHA-256), hardware identity, firmware versions, model hashes, baseline TTFT/throughput, and verified recovery procedures.

**Continuous existence:** No structural change. Also baseline host cold-start behavior, model reload time, and measurable state-restoration behavior. Config A remains the historical comparison.

#### Step 2: Create the Native Boot Spine
Make the DGX Spark reach AIENOS code directly from UEFI firmware (`_start` / `efi_main`). The milestone requires that AIENOS owns CPU execution, initial physical memory, timer/interrupt setup, early UART console output (`0x16A00000`), and a deterministic panic/halt loop (`wfi`).

**Continuous existence:** The boot spine initializes the physical machine. It does not define or create an AIEN identity. No `LogicalAgentId` is minted merely because Gate 2 code starts.

#### Step 3: Integrate `aienos-kernel` on Real Hardware
Transition the frame allocator, spinlocks, and SHA-256 hashing from host-compiled tests into the native bare-metal execution environment.

**Continuous existence:** Kernel lifetime must not equal agent lifetime. Interfaces must allow durable logical state to outlive kernel restart, scheduler reconstruction, and allocator reconstruction. No persistent agent identifier may derive solely from volatile kernel identifiers.

#### Step 4: Bring Up Native Storage (ADR 0003)
Implement the minimal native storage machinery necessary to discover partitions, read immutable content-addressed model extents (`model/<hash>`), read/write committed Cortex checkpoints, and safely replay/truncate the WAL. No POSIX filesystem required.

**Continuous existence:** First major continuity foundation. The AIEN System Store must persistently represent at least: provisioned `LogicalAgentId` / agent root, committed logical state, Cortex checkpoints/WAL foundation, branch/state manifests, immutable artifact references, and continuity metadata. Qualification proves committed semantic data survives native storage round trips. No model required.

#### Step 5: Prove Recovery Core Before the Model (ADR 0006)
Before any AI model boots autonomously, deliberately inject a fault (corrupt model extent, corrupt uncommitted WAL tail). Prove the operator can enter Recovery Core, authenticate with offline credentials, inspect the raw system record, and roll back to a known-good slot with zero model involvement.

**Continuous existence — identity-loss refusal (mandatory):** Corrupt or remove the active execution environment while leaving a valid durable AIEN identity. Recovery must (1) locate the valid durable identity, (2) authenticate the operator, (3) restore or select the valid system state, and (4) preserve the same `LogicalAgentId`. If no valid durable AIEN identity can be recovered, Recovery must stop and ask the operator. It must not silently create a new identity.

#### Step 6: Integrate Agent State + Cortex (The Real Phase 3 Gate)
Boot the system, create/modify logical agent state, persist it to the native object store, power cycle the machine, reconstruct the state, and prove that the exact same `LogicalAgentId` and causal branch lineage return.

**Continuous existence — first empirical qualification:** `LogicalAgentId = X` → create Cortex/branch/task state → commit → full power cycle → cold native start → recover → same `LogicalAgentId = X`. Proof must show preserved committed Cortex state, branch lineage, durable task metadata, WAL handling of uncommitted tails, and no hidden replacement identity. Only after this passes: *AIEN logical identity survives a real Spark power cycle.*

#### Step 7: Load Inference
Bring up local quantized CPU inference (e.g. 1B parameter GGUF). The acceptance condition is continuity: power on → native AIENOS → persistent agent → local model → console dialogue → reboot → continuity.

**Continuous existence:** Identity X → model loads → conversation continues → model unload/reboot/reload → same identity X → conversation/state continuity preserved. The model must be replaceable/reloadable beneath the same logical agent. Proves inference execution can disappear and return without redefining AIEN.

#### Step 8: Integrate AEGIS and Worlds
Execute the agent inside a transactional J-Space World. Verify that all outbound network attempts (DNS, TCP, TLS) fail closed unless covered by an explicit pre-authorized Standing Capability. Verify that discarding a World completely reverts file deltas.

**Continuous existence:** Durable authorization semantics must survive sleep/recovery. Persist what must persist; do not persist temporary authority scoped to a single volatile session unless policy says otherwise. A wake/restart must never accidentally broaden capability authority.

#### Step 9: Integrate the C1 Physical Tree
Connect the C1 Copy-On-Write tree to live inference KV state. Enforce transactional reservations before step admission, verify that a 10,000-token shared prefix allocates zero duplicate KV pages across child branches, and verify recomputation equivalence on memory pressure.

**Continuous existence:** Mandatory cases include live branch → physical KV discarded → logical branch preserved → KV reconstructed → equivalence passes; and branch committed → deep-sleep simulation → all physical KV gone → logical state restored → reconstruction → same `LogicalBranchId`. Empirically binds *losing KV costs computation, not identity* to the native OS lifecycle.

#### Step 10: Pursue Native Hardware Acceleration
With native correctness mathematically proven, introduce direct MMIO accelerator paths to the NVIDIA GB10, measuring performance against Config A (Ubuntu reference) and Config B (minimal Linux compatibility island).

**Continuous existence:** Accelerator state is Class B reconstructible physical state unless explicitly proven otherwise. Optimize warm wake, model/branch residency, KV preservation, and state reconstruction—never make identity depend on preserving accelerator state. Lifecycle metrics (wake-to-continuation, reconstruction latencies) join the Config A/B/C report without replacing boot metrics.
