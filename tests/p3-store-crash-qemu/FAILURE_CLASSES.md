# Subagent G5 Review Report: P3 Store Crash/Reboot Qualification Harness

**To:** Parent Agent (`d3eee977-e1bb-498c-98e3-98fc48e87cf2`)  
**From:** Subagent G5 (Failure-Class Reviewer)  
**Branch:** `test/p3-store-crash-qemu`  
**Repository:** `aien-dev/aienos`  

---

### Executive Findings & Architectural Notes

1. **Crash Checkpoints Review**:
   All 11 mandatory crash checkpoints have been rigorously reviewed against ADR 0015 (System Store v1 Format) and the transaction commit protocol implemented in `crates/aienos-kernel/src/store/v1.rs` and `fault.rs`. The transition points cleanly divide into:
   - Checkpoints 1–8: Pre-superblock arena staging (payload, catalog, commit record, and barrier 1).
   - Checkpoints 9–10: Superblock staging and barrier 2.
   - Checkpoint 11: Durable commit point (barrier 2 acknowledged).

2. **Disk Cache & QEMU Caching Physics**:
   - `cache=unsafe`: **Strictly Prohibited**. Masks missing guest flushes and allows host memory to fake durability across QEMU power cuts.
   - `cache=writeback`: **Unacceptable for Qualification**. Subject to host OS kernel dirty page writeback reordering and host page cache retention across guest `SIGKILL`.
   - `cache=directsync`: **Mandatory**. Employs `O_DIRECT | O_SYNC`, ensuring zero host page cache buffering. Guest flush commands map directly to physical flush barriers. Any sudden power cut or process termination accurately reflects disk media durability.

3. **Critical Protocol Divergence Identified**:
   - **ADR 0015 §3** defines `CommitRecord` semantic bytes as exactly **200 bytes** ending at `committed_high_water` (offset 192..200).
   - **`crates/aienos-kernel/src/store/v1.rs`** encodes `CommitRecord` as **232 bytes**, adding `published_manifest_id: ObjectId` (offset 200..232).
   - *Recommendation*: The qualification suite and oracle must treat the 232-byte layout as normative for Store v1 if published manifest support is included, and ADR 0015 must be updated to avoid CRC/hash calculation mismatches.

4. **Review Document**:
   Below is the complete, comprehensive specification document produced for `tests/p3-store-crash-qemu/FAILURE_CLASSES.md`.

---

```markdown
# P3 System Store v1 Crash/Reboot Qualification: Failure Classes, Cache Flushing Physics, and Oracle Invariants

## Document Metadata
- **Target Subsystem:** AIENOS System Store v1 (`crates/aienos-kernel/src/store/`)
- **Qualification Scope:** QEMU AArch64 Crash & Reboot Power-Cut Qualification Harness
- **Branch:** `test/p3-store-crash-qemu`
- **Governing Architecture:** ADR 0015 (System Store v1 Format), ADR 0003 (Minimal Object Store), ADR 0006 (Deterministic Recovery Core)
- **Role:** Subagent G5 (Failure-Class Reviewer)

---

## 1. Executive Summary & Architecture Baseline

AIENOS System Store v1 provides a crash-consistent, append-only, content-addressed persistent storage substrate for sovereign bare-metal and virtualized execution. The system guarantees that arbitrary crashes, torn writes, power cuts, or hypervisor terminations leave the store in a strictly verifiable state: either rolling back to the previous intact generation ($N$) or advancing to the newly committed generation ($N+1$). Intermediate, partial, torn, or fabricated states are rejected deterministically by the storage oracle.

### 1.1 Layering Architecture

Storage operations adhere to a strict unidirectional layering:
```
Physical / Emulated Block Device (NVMe / VirtIO-Blk)
                      │
                      ▼
         BoundedBlockDevice (LBA Bounds Check)
                      │
                      ▼
            StoreDevice (4096-Byte Store Units)
                      │
                      ▼
    System Store v1 (Transaction & Recovery Engine)
```

1. **`BlockDevice`**: Physical or emulated driver exposing sector read, write, and flush primitives (logical block size 512 or 4096 bytes).
2. **`BoundedBlockDevice`**: Enforces strict geometry partitioning. Local LBAs map to `start_lba + local_lba`. All requests crossing `block_count` fail with `BlockError::OutOfRange`.
3. **`StoreDevice`**: Exposes fixed 4096-byte Store Units. Directly maps 1 unit to eight 512-byte blocks or one 4096-byte block. Employs **zero read-modify-write**.
4. **`System Store v1`**: Manages dual alternating superblocks (Unit 0 = Slot A, Unit 1 = Slot B), content-addressed application objects (Units 2+), lexicographical catalogs, commit records, and cryptographic root selection.

### 1.2 Cryptographic Chain of Authority

A persistent root is never trusted based on sector readability alone. Authority flows through an unbroken cryptographic dependency chain:

$$\text{Bounded Region} \longrightarrow \text{Superblock CRC-32C} \longrightarrow \text{SHA-256 CommitRecord} \longrightarrow \text{SHA-256 Catalog} \longrightarrow \text{Sorted Descriptors} \longrightarrow \text{SHA-256 Objects} \longrightarrow \text{Monotonic Generation}$$

- **Superblock Integrity**: Protected by Castagnoli CRC-32C (polynomial `0x82f63b78`) over all 4096 bytes with CRC field (bytes 168..172) zeroed during calculation. Bytes 172..4096 MUST be zero.
- **CommitRecord Integrity**: Addressed by its domain-separated SHA-256 `ObjectId` ($KIND=2, VERSION=1$). Binds the generation, previous commit ID, previous catalog ID, new catalog ID, and committed high-water mark.
- **Catalog Integrity**: Addressed by its domain-separated SHA-256 `ObjectId` ($KIND=1, VERSION=1$). Contains entries sorted lexicographically by 32-byte `ObjectId`.
- **Application Object Integrity**: Addressed by domain-separated SHA-256 `ObjectId` over `(Domain || Kind || Version || ByteLength || SemanticBytes)`.

---

## 2. Complete Transaction Append & Flush Protocol

Every transaction commits atomically via a two-phase barrier append sequence. No blocks are overwritten in place except the alternating inactive superblock unit.

### 2.1 Canonical Write Sequence

```
[Arena Tail]                                                [Superblock Unit]
      │                                                             │
      ├─► Step 1: Write Application Payload Objects                 │
      ├─► Step 2: Write Catalog Object                              │
      ├─► Step 3: Write CommitRecord Object                         │
      │                                                             │
      ▼                                                             │
 [FLUSH 1: Barrier 1 (SYNCHRONIZE CACHE / NVMe Flush)]              │
      │                                                             │
      │   (Arena Payload & Metadata Durably Persisted to Media)     │
      │                                                             ▼
      │                                            Step 5: Write Inactive Superblock
      │                                                             │
      ▼                                                             ▼
 [FLUSH 2: Barrier 2 (SYNCHRONIZE CACHE / NVMe Flush)] <────────────┘
      │
      ▼
 [COMMIT POINT: Generation N+1 Officially Authoritative]
```

- **Step 0 (Preflight Validation)**: Before any I/O is submitted, the transaction engine checks all object lengths, unit requirements, catalog entry bounds, lexicographical ordering, duplicate IDs, arithmetic overflow, and bounded-region capacity. Any error aborts with **zero persistent writes**.
- **Step 1 (Payload Extents)**: New application objects are appended contiguously starting at `prior_committed_high_water_unit`.
- **Step 2 (Catalog Extent)**: Complete immutable new Catalog is appended immediately after payload extents.
- **Step 3 (CommitRecord Extent)**: Exact single-unit CommitRecord is appended immediately after the Catalog. The new high-water mark is `commit_unit + 1`.
- **Step 4 (Barrier 1 - FLUSH 1)**: Driver issues flush/sync command. This guarantees that all payload blocks, catalog blocks, and the commit record block have migrated from volatile drive DRAM write cache into non-volatile media.
- **Step 5 (Inactive Superblock Write)**: The inactive superblock slot ($Slot = \text{generation} \pmod 2$) is written with generation $N+1$, referencing the new CommitRecord and Catalog, protected by CRC-32C.
- **Step 6 (Barrier 2 - FLUSH 2 / Commit Point)**: Driver issues final flush/sync command. Once media acknowledges this flush, generation $N+1$ is durably authoritative.

---

## 3. Crash Checkpoint & Failure Class Taxonomy

The qualification harness evaluates eleven discrete crash checkpoints spanning the transaction lifecycle. Each checkpoint models a distinct physical media state and demands an unambiguous oracle classification.

```
       Step 1: Payload       Step 2: Catalog   Step 3: CommitRecord         Step 5: Superblock
     ┌─────────────────┐    ┌───────────────┐ ┌────────────────────┐       ┌──────────────────┐
───► │ P1 │ P2 │ ...   │ ─► │ Cat Unit(s)   │ │ Commit Unit        │ ─►[F1]│ Inactive SB Unit │ ─►[F2]
     └─────────────────┘    └───────────────┘ └────────────────────┘       └──────────────────┘
   ▲   ▲                  ▲   ▲             ▲   ▲                    ▲   ▲   ▲                  ▲    ▲
   │   │                  │   │             │   │                    │   │   │                  │    │
  CP1 CP2                CP3 CP4           CP5 CP6                  CP7 CP8 CP9                CP10 CP11
```

### Checkpoint 1: Before First Write
- **Execution Point**: Preflight checks complete; in-memory staging ready; no disk write command submitted.
- **Physical Media State**: Exact pre-transaction state. Units `[0, high_water_N)` intact. Superblock $N$ authoritative.
- **Oracle Classification**: `ValidStore` at generation $N$.
- **Oracle Verdict**: **Strict Rollback to OLD**. Zero high-water advancement. Zero allocation leaks.

### Checkpoint 2: During Payload Writes
- **Execution Point**: Mid-transfer of application payload objects. Injected via `WriteFault` on write calls $1 \dots P$ with partial byte prefix.
- **Physical Media State**: Partially written, torn payload blocks located at $\ge \text{high\_water}_N$. Active superblock $N$ points to previous clean catalog and high-water mark.
- **Oracle Classification**: `ValidStore` at generation $N$.
- **Oracle Verdict**: **Strict Rollback to OLD**. Torn blocks exist strictly beyond `high_water_N` and are treated as non-existent.

### Checkpoint 3: After Payload Writes
- **Execution Point**: All payload objects written to controller buffer; Catalog write has not commenced.
- **Physical Media State**: Complete payload extents written past $\text{high\_water}_N$. No new catalog or commit record on media. Active superblock $N$ unchanged.
- **Oracle Classification**: `ValidStore` at generation $N$.
- **Oracle Verdict**: **Strict Rollback to OLD**. Payload extents beyond high-water mark remain unreferenced orphaned units.

### Checkpoint 4: During Catalog Write
- **Execution Point**: Mid-transfer of Catalog units. Injected via `WriteFault` on catalog write call.
- **Physical Media State**: Torn catalog unit (partial magic, truncated entries, or invalid checksum) past high-water mark. Active superblock $N$ unchanged.
- **Oracle Classification**: `ValidStore` at generation $N$.
- **Oracle Verdict**: **Strict Rollback to OLD**. Torn catalog block is unreferenced by active superblock.

### Checkpoint 5: After Catalog Write
- **Execution Point**: Catalog units fully written; CommitRecord write has not commenced.
- **Physical Media State**: Payload and Catalog units present in append arena. CommitRecord absent. Active superblock $N$ unchanged.
- **Oracle Classification**: `ValidStore` at generation $N$.
- **Oracle Verdict**: **Strict Rollback to OLD**. Catalog and payload units remain uncommitted tail.

### Checkpoint 6: During CommitRecord Write
- **Execution Point**: Mid-transfer of the 4096-byte CommitRecord unit. Injected via `WriteFault` on commit write call.
- **Physical Media State**: Partial CommitRecord unit (corrupt magic, incomplete fields, or torn trailing bytes). Active superblock $N$ unchanged.
- **Oracle Classification**: `ValidStore` at generation $N$.
- **Oracle Verdict**: **Strict Rollback to OLD**. Corrupt commit unit is unreferenced by active superblock.

### Checkpoint 7: Before First Flush (Barrier 1 Missing)
- **Execution Point**: CommitRecord write call returned from driver to controller buffer, but `FLUSH 1` has not completed. Power cut.
- **Physical Media State**: Payload, Catalog, and CommitRecord reside in volatile drive DRAM write cache. Due to out-of-order write retirement, some blocks may have reached flash while others were lost. Active superblock $N$ intact.
- **Oracle Classification**: `ValidStore` at generation $N$.
- **Oracle Verdict**: **Strict Rollback to OLD**. Active superblock $N$ continues to govern.

### Checkpoint 8: After First Flush (Barrier 1 Acknowledged)
- **Execution Point**: `FLUSH 1` acknowledged by drive firmware. Inactive superblock write has not commenced.
- **Physical Media State**: Entire generation $N+1$ payload, catalog, and commit record are durably committed to non-volatile flash. Active superblock $N$ remains authoritative. Inactive superblock contains stale generation $N-1$ (or zero).
- **Oracle Classification**: `ValidStore` at generation $N$.
- **Oracle Verdict**: **Strict Rollback to OLD**. Even though an entire intact generation $N+1$ object graph rests on physical media, it lacks root authority.

### Checkpoint 9: During Inactive Superblock Write
- **Execution Point**: Mid-transfer of the 4096-byte inactive superblock unit. Injected via torn write at sector offsets $0 \dots 4096$.
- **Physical Media State**: Inactive superblock slot contains torn data (invalid magic, damaged fields, or failed CRC-32C). Active superblock slot remains intact at generation $N$.
- **Oracle Classification**: `ValidStore` at generation $N$ (or `DegradedRecovery` if older root requires single-slot mount).
- **Oracle Verdict**: **Strict Rollback to OLD**. Damaged superblock slot fails CRC-32C check; valid active slot $N$ is chosen.

### Checkpoint 10: Before Final Flush (Barrier 2 Missing)
- **Execution Point**: Inactive superblock write acknowledged to controller buffer, but `FLUSH 2` has not completed. Power cut.
- **Physical Media State**: Inactive superblock unit resides in volatile controller cache or is partially committed across NAND flash pages.
- **Oracle Classification**: 
  - If superblock was torn or lost on power loss: `ValidStore` at generation $N$ (bad CRC on inactive slot).
  - If superblock fully hit flash: Generation $N+1$ has valid CRC and valid graph. However, because `FLUSH 2` was unacknowledged, the transaction cannot be assumed committed.
- **Oracle Verdict**: **Strict Rollback to OLD**. The qualification oracle enforces that without an acknowledged final flush barrier, state must revert to OLD.

### Checkpoint 11: After Final Flush (Commit Point)
- **Execution Point**: `FLUSH 2` acknowledged by drive firmware. Power cut occurs anytime afterward.
- **Physical Media State**: Superblock $N+1$ durably persisted in flash with valid CRC-32C, pointing to durable CommitRecord $N+1$, Catalog $N+1$, and payload objects. Slot $N$ contains valid generation $N$.
- **Oracle Classification**: `ValidStore` at generation $N+1$.
- **Oracle Verdict**: **Roll Forward to NEW**. Monotonic generation advances ($N \to N+1$). All newly added objects are accessible.

---

## 4. Disk Cache Dynamics, Barrier Physics & QEMU Caching Modes

### 4.1 Physical Storage Controller Write Buffering

Modern NVMe and SATA storage devices utilize internal volatile DRAM buffers to accelerate writes. When the host issues a write request:
1. Controller stages sectors into volatile DRAM and signals immediate completion to host.
2. Controller background firmware schedules out-of-order writeback to non-volatile NAND flash blocks.
3. If power fails prior to an explicit cache flush, unwritten DRAM contents vanish instantly, and partially written flash blocks suffer sector tears.

Without explicit barriers, a drive controller may reorder writes such that the inactive Superblock lands in flash *before* the CommitRecord or Catalog blocks land in flash. A power cut at that precise instant leaves a valid Superblock pointing to unwritten flash garbage.

### 4.2 Barrier Physics: The Dual-Flush Requirement

Store v1 defeats write reordering through two mandatory flush barriers:
1. **Flush Barrier 1 (`FLUSH 1`)**: Issued after all arena writes (payload, catalog, commit record). Guarantees the complete object graph is durable on flash before the superblock pointer is modified.
2. **Flush Barrier 2 (`FLUSH 2`)**: Issued after the inactive superblock is written. Guarantees root authority is durable on flash. This barrier is the **atomic commit point**.

### 4.3 Analysis of QEMU Storage Caching Modes

The qualification harness executes inside QEMU AArch64 using emulated block devices (`virtio-blk-pci` or `nvme`). The choice of QEMU disk cache mode directly dictates whether crash testing reflects physical hardware reality or produces false qualification passes.

```
+------------------+-------------------+--------------------+------------------------+---------------------------------------+
| QEMU Cache Mode  | Host Page Cache   | Guest Flush Action | Behavior on Power-Cut  | Suitability for Qualification         |
+------------------+-------------------+--------------------+------------------------+---------------------------------------+
| cache=unsafe     | Enabled (Dirty)   | Completely Ignored | Total data loss/chaos  | FATAL: False passes / false failures  |
| cache=writeback  | Enabled (Dirty)   | Calls fdatasync()  | Buffered in host RAM   | UNACCEPTABLE: Host RAM masks crashes  |
| cache=writethrough| Enabled (Clean)  | Calls fdatasync()  | Writes sync, reads buf | FLAWED: Read caching & high latency   |
| cache=directsync | Bypassed (DIRECT) | Direct HW Barrier  | True hardware fidelity | MANDATORY: Exact physical semantics   |
+------------------+-------------------+--------------------+------------------------+---------------------------------------+
```

#### Why `cache=unsafe` is Prohibited
- `cache=unsafe` sets `BDRV_O_NO_FLUSH`. QEMU discards all flush requests from the guest kernel.
- If guest storage code forgets to issue `FLUSH 1`, `cache=unsafe` will not expose the omission.
- If QEMU is killed via `SIGKILL`, unwritten blocks buffered in host memory can be dropped out of order, creating synthetic corruption that does not correspond to guest behavior.

#### Why `cache=writeback` is Unacceptable for Qualification
- Guest writes enter the host OS page cache.
- When the test harness simulates a power cut by terminating QEMU (`kill -9`), host page cache memory **survives** in the Linux host kernel.
- If the test script subsequently inspects the raw backing disk image from the host, it reads host dirty cache lines that were never flushed, falsely certifying unpersisted writes as durable.

#### Why `cache=directsync` is Mandatory
- Combines `O_DIRECT | O_SYNC` (`BDRV_O_NOCACHE`). Host OS page cache is completely bypassed.
- Guest DMA transfers write synchronously down to the physical drive or host filesystem storage engine without intermediate buffering.
- When guest driver executes `flush`, it triggers a synchronous hardware sync barrier (`fdatasync` down to hardware non-volatile queue).
- A `SIGKILL` of the QEMU process guarantees that only durably acknowledged writes exist on the backing file, completely eliminating host buffering artifacts.

### 4.4 Device Interface & Command Verification

The harness must qualify both primary virtual storage interfaces:
1. **VirtIO-Block (`virtio-blk-pci`)**:
   - Write commands: `VIRTIO_BLK_T_OUT`.
   - Barrier commands: `VIRTIO_BLK_T_FLUSH`. The driver MUST negotiate `VIRTIO_BLK_F_FLUSH` (bit 9). If the feature is missing or unnegotiated, store mounts must refuse write operations.
2. **NVMe Controller (`nvme`)**:
   - Write commands: Opcode `0x01` (`Write`).
   - Barrier commands: Opcode `0x00` (`Flush`). The driver MUST verify the Volatile Write Cache (`VWC`) bit in the Identify Controller structure and dispatch explicit Flush commands to Namespace 1.

---

## 5. Oracle Invariant Verification Rules & Illegal State Ledger

The storage qualification oracle verifies disk state on reboot following an injected crash. It enforces the **Golden Decision Boundary** and inspects the persistent structures against six categorically forbidden illegal states.

```
                          [THE GOLDEN DECISION BOUNDARY]
                                        │
 Checkpoints 1 through 10               │ Checkpoint 11
 (Prior to Final Commit Flush)          │ (After Final Commit Flush)
────────────────────────────────────────┼───────────────────────────────────────►
 MUST ROLL BACK TO OLD (Gen N)          │ MUST ROLL FORWARD TO NEW (Gen N+1)
 No uncommitted state visible           │ All new objects atomically visible
 Inactive slot rejected or ignored      │ Inactive slot promoted to active root
```

### 5.1 The Six Forbidden Illegal States

The oracle asserts that under no combination of crash points, torn writes, or power failures may the storage engine enter or permit any of the following states:

#### Illegal State 1: Mixed Catalog / Object Graph
- **Definition**: An active Catalog containing a mixture of generation $N$ and generation $N+1$ descriptors, or referencing objects that were partially written or uncommitted.
- **Verification Rule**: Every descriptor in the active Catalog must resolve to contiguous units within $[2, \text{committed\_high\_water})$, and the SHA-256 hash of its semantic bytes must equal its `ObjectId`.

#### Illegal State 2: Partially Authoritative New Root
- **Definition**: A Superblock updated to generation $N+1$ whose referenced CommitRecord or Catalog failed validation, or an active root whose fields do not match its referenced CommitRecord.
- **Verification Rule**: A superblock alone never establishes authority. The superblock's `generation`, `store_uuid`, `commit_record_id`, `catalog_id`, `committed_high_water`, and geometry MUST bitwise match the validated CommitRecord.

#### Illegal State 3: Fabricated Generation
- **Definition**: A superblock or commit record claiming an arbitrary generation leap ($N \to N+2$), or incrementing generation without a valid cryptographic predecessor link.
- **Verification Rule**: For any generation $G > 1$, the CommitRecord must satisfy:
  $$\text{previous\_generation} = G - 1$$
  $$\text{previous\_commit\_id} = \text{ObjectId}(\text{CommitRecord}_{G-1})$$
  $$\text{previous\_catalog\_id} = \text{ObjectId}(\text{Catalog}_{G-1})$$

#### Illegal State 4: Root Past Durable High-Water
- **Definition**: A superblock or commit record claiming a `committed_high_water_unit` that exceeds the total number of units physically written and flushed, or pointing to units outside $[0, \text{region\_units})$.
- **Verification Rule**: All referenced extents must satisfy $\text{first\_unit} + \text{unit\_count} \le \text{committed\_high\_water} \le \text{region\_units}$.

#### Illegal State 5: Silent Repair / Automatic Healing / Autoformat
- **Definition**: The storage layer during `open()` or mount attempting to write, zero, reformat, or "fix" bad CRCs, torn descriptors, or uncommitted tails.
- **Verification Rule**: ADR 0015 strictly mandates that `open()` is side-effect-free. Storage media must remain byte-identical before and after a failed or degraded mount.

#### Illegal State 6: Mutation During Read-Only Recovery
- **Definition**: Any write I/O issued to storage while operating under degraded recovery or read-only mount mode.
- **Verification Rule**: When mounted in `DegradedRecovery` (e.g. valid older root available after newer root suffered corruption), write operations must return `StoreError::ReadOnlyRecovery` and zero write commands may be dispatched to the device.

---

## 6. Oracle Invariant Verification Matrix

| Checkpoint ID | Crash Checkpoint Name | Injected Failure / Fault Trigger | Physical Media State at Crash | Expected Mount Classification | Expected Authoritative Root | Primary Invariant Proved | Rejection / Failure Criteria |
|---|---|---|---|---|---|---|---|
| **CP-01** | Before First Write | Preflight failure or abort prior to 1st I/O | Media 100% untouched | `ValidStore` | **OLD (Gen N)** | Atomic Non-Interference | Any write I/O dispatched; corrupt media |
| **CP-02** | During Payload Writes | Torn write on payload block ($1 \dots P$) | Torn blocks at $\ge \text{high\_water}_N$ | `ValidStore` | **OLD (Gen N)** | High-Water Isolation | Active catalog exposes torn payload object |
| **CP-03** | After Payload Writes | Crash before catalog write begins | Valid payload past high-water; no catalog | `ValidStore` | **OLD (Gen N)** | Uncommitted Append Safety | Orphaned payload promoted to active catalog |
| **CP-04** | During Catalog Write | Torn write on catalog unit | Corrupt catalog unit past high-water | `ValidStore` | **OLD (Gen N)** | Metadata Crash Independence | Corrupt catalog unit evaluated as valid root |
| **CP-05** | After Catalog Write | Crash before commit record write | Payload + Catalog intact; no commit record | `ValidStore` | **OLD (Gen N)** | Commit Record Requirement | Catalog promoted without authoritative commit |
| **CP-06** | During CommitRecord | Torn write on CommitRecord unit | Damaged CommitRecord unit past high-water | `ValidStore` | **OLD (Gen N)** | Commit Atomicity | Incomplete commit record parsed as valid |
| **CP-07** | Before First Flush | Power cut before `FLUSH 1` completion | Tail in volatile DRAM; missing barrier 1 | `ValidStore` | **OLD (Gen N)** | Barrier 1 Requirement | Reordered writes corrupt generation N root |
| **CP-08** | After First Flush | Power cut after `FLUSH 1`; before SB write | Complete Gen $N+1$ tail in flash; SB untouched | `ValidStore` | **OLD (Gen N)** | Uncommitted Durable Tail Safety | Durable tail accepted without SB promotion |
| **CP-09** | During Inactive SB Write | Torn write on inactive superblock unit | Inactive slot has bad CRC / torn bytes | `ValidStore` / `DegradedRecovery` | **OLD (Gen N)** | Dual-Root CRC Disambiguation | Torn superblock accepted; panics on bad CRC |
| **CP-10** | Before Final Flush | Power cut before `FLUSH 2` completion | Inactive SB in volatile DRAM; missing barrier 2 | `ValidStore` | **OLD (Gen N)** | Barrier 2 Requirement | Unflushed superblock treated as commit point |
| **CP-11** | After Final Flush | Crash anytime after `FLUSH 2` acknowledged | Both SB valid; Slot $N+1$ points to Gen $N+1$ | `ValidStore` | **NEW (Gen N+1)** | Atomicity & Monotonic Progress | Fails forward progress; rolls back after flush |

---

## 7. QEMU Qualification Harness Implementation Contract

### 7.1 QEMU Invocation Specification

To ensure hardware-faithful execution and prevent host caching distortions, QEMU must be invoked with the following parameters:

```bash
# Architecture & Machine
QEMU_ARCH="qemu-system-aarch64"
QEMU_MACHINE="-M virt,virtualization=on,gic-version=3 -accel tcg,thread=single -cpu max -smp 4 -m 2048"

# Firmware & Variable Store (Disposable vars.fd)
QEMU_FW="-drive if=pflash,format=raw,readonly=on,file=${AAVMF_CODE} \
         -drive if=pflash,format=raw,file=${WORK_DIR}/vars.fd"

# Storage Configuration: MANDATORY directsync and direct hardware mapping
# VirtIO-Block Configuration
QEMU_VIRTIO_BLK="-drive if=none,id=store0,format=raw,cache=directsync,aio=io_uring,file=${STORE_IMAGE} \
                -device virtio-blk-pci,drive=store0,bootindex=2"

# NVMe Configuration (Alternative target)
QEMU_NVME="-drive if=none,id=nvme0,format=raw,cache=directsync,aio=io_uring,file=${STORE_IMAGE} \
           -device nvme,drive=nvme0,serial=AIENOS_STORE_QUAL"

# Non-Interactive Serial Capture
QEMU_CONSOLE="-serial file:${WORK_DIR}/serial.log -display none -nic none -no-reboot"
```

### 7.2 Fault Injection Execution Protocol

The automated test runner executes the following sequential steps for each matrix case:

```
[Create Golden Base Image] ───► [Arm Fault Plan in Kernel/Device] ───► [Execute QEMU Transaction Boot]
                                                                                  │
                                                                           (Power Cut / Crash)
                                                                                  │
[Parse Verification Receipt] ◄── [Evaluate Oracle Invariants] ◄─── [Reboot QEMU in Recovery Mode]
```

1. **Step 1 (Base Staging)**: Initialize a deterministic Store v1 disk image formatted at Generation $N$ with known payload objects and catalog entries.
2. **Step 2 (Fault Plan Configuration)**: Configure the candidate kernel with `FaultPlan { write, flush }` targeting the specific checkpoint (e.g. write call index and byte offset).
3. **Step 3 (Crash Boot)**: Launch QEMU. The candidate attempts the transaction. Upon hitting the fault point, the fault injector simulates torn I/O and triggers system reset or immediate hypervisor termination (`SIGKILL`).
4. **Step 4 (Reboot Verification)**: Relaunch QEMU with the untouched backing file in read-only verification mode. The candidate mounts the store, outputs structured diagnostic records, and halts.
5. **Step 5 (Oracle Evaluation)**: The host harness verifies:
   - Serial log contains canonical markers (`STORE_MOUNT: PASS`, `ROOT_GENERATION: N`).
   - Disk image satisfies the exact binary invariants of the Oracle Matrix.
   - Generates a signed qualification receipt (`AIENOS_P3_STORE_RECEIPT`).

---

## 8. Alignment Checklist & Recommendations

1. **CommitRecord Wire Size Alignment**:
   - Resolve divergence between ADR 0015 (200 bytes) and `crates/aienos-kernel/src/store/v1.rs` (232 bytes, adding `published_manifest_id: ObjectId`). Update ADR 0015 to include `published_manifest_id` before format lock.
2. **Crash Test Harness Location**:
   - Commit this document to `tests/p3-store-crash-qemu/FAILURE_CLASSES.md`.
   - Place the automated runner in `scripts/qemu_p3_store_crash_test.sh` integrating directly into `scripts/verify_all.sh`.
3. **Evidence Archival**:
   - Log serial captures, binary diffs, and verification receipts under `evidence/p3_store_crash_qemu_YYYY-MM-DD.txt`.
```
