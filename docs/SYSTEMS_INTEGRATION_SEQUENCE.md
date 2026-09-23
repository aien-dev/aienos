# AIENOS Systems Integration Sequence & Epistemic Calibration

> **Status:** Governing Integration Framework
> **Authority:** Operator Directive (2026-09-23)
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

#### Step 1: Finish Config A Freeze
Capture the working Linux/NVIDIA reference baseline on the DGX Spark into `evidence/config_a_reference_bundle.json` with cryptographic digests (SHA-256), hardware identity, firmware versions, model hashes, baseline TTFT/throughput, and verified recovery procedures.


#### Step 2: Create the Native Boot Spine
Make the DGX Spark reach AIENOS code directly from UEFI firmware (`_start` / `efi_main`). The milestone requires that AIENOS owns CPU execution, initial physical memory, timer/interrupt setup, early UART console output (`0x16A00000`), and a deterministic panic/halt loop (`wfi`).


#### Step 3: Integrate `aienos-kernel` on Real Hardware
Transition the frame allocator, spinlocks, and SHA-256 hashing from host-compiled tests into the native bare-metal execution environment.


#### Step 4: Bring Up Native Storage (ADR 0003)
Implement the minimal native storage machinery necessary to discover partitions, read immutable content-addressed model extents (`model/<hash>`), read/write committed Cortex checkpoints, and safely replay/truncate the WAL. No POSIX filesystem required.


#### Step 5: Prove Recovery Core Before the Model (ADR 0006)
Before any AI model boots autonomously, deliberately inject a fault (corrupt model extent, corrupt uncommitted WAL tail). Prove the operator can enter Recovery Core, authenticate with offline credentials, inspect the raw system record, and roll back to a known-good slot with zero model involvement.


#### Step 6: Integrate Agent State + Cortex (The Real Phase 3 Gate)
Boot the system, create/modify logical agent state, persist it to the native object store, power cycle the machine, reconstruct the state, and prove that the exact same `LogicalAgentId` and causal branch lineage return.


#### Step 7: Load Inference
Bring up local quantized CPU inference (e.g. 1B parameter GGUF). The acceptance condition is continuity: power on → native AIENOS → persistent agent → local model → console dialogue → reboot → continuity.


#### Step 8: Integrate AEGIS and Worlds
Execute the agent inside a transactional J-Space World. Verify that all outbound network attempts (DNS, TCP, TLS) fail closed unless covered by an explicit pre-authorized Standing Capability. Verify that discarding a World completely reverts file deltas.


#### Step 9: Integrate the C1 Physical Tree
Connect the C1 Copy-On-Write tree to live inference KV state. Enforce transactional reservations before step admission, verify that a 10,000-token shared prefix allocates zero duplicate KV pages across child branches, and verify recomputation equivalence on memory pressure.


#### Step 10: Pursue Native Hardware Acceleration
With native correctness mathematically proven, introduce direct MMIO accelerator paths to the NVIDIA GB10, measuring performance against Config A (Ubuntu reference) and Config B (minimal Linux compatibility island).
