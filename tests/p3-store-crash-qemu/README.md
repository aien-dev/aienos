# P3 System Store Crash & Reboot Qualification Harness

This directory contains the automated multi-run qualification harness for **AIENOS System Store v1 (ADR 0015)** crash consistency, reboot durability, and recovery guarantees in QEMU AArch64.

---

## 1. Overview and Architecture

The harness coordinates five specialized components to validate that Store v1 maintains transactional atomicity, monotonic generation advancement, and strict fail-safe rollback across all possible hardware power-loss or reset boundaries:

```
+-----------------------------------------------------------------------------------------------+
|                      G4: Reboot Campaign Orchestrator (run_campaign.sh)                       |
+-----------------------------------------------------------------------------------------------+
         |                                    |                                    |
         v                                    v                                    v
+------------------+                +--------------------+               +--------------------+
|  G1: Disposable  |                |  G2: Deterministic |               |  G3: Independent   |
|  Disk Lifecycle  |                |  Crash Controller  |               |  Image Inspector   |
| (disk_lifecycle) |                | (crash_controller) |               |   (inspector.py)   |
+------------------+                +--------------------+               +--------------------+
         |                                    |                                    |
         +------------------------------------+------------------------------------+
                                              |
                                              v
                              +-------------------------------+
                              |    QEMU NVMe directsync Host   |
                              |   -drive ...,cache=directsync |
                              |   -device nvme,serial=...     |
                              +-------------------------------+
                                              |
                                              v
                              +-------------------------------+
                              |     G5: Failure Classes &     |
                              |     Verification Matrix       |
                              |     (FAILURE_CLASSES.md)      |
                              +-------------------------------+
```

### Component Roles
- **G1 (Disposable Disk Lifecycle - `disk_lifecycle.sh`)**: Creates deterministic base raw block images, creates isolated copy-on-write / ephemeral test instances, computes SHA-256 pre-run and post-run digests, enforces strict isolation against physical devices or host filesystems, and safely wipes instances.
- **G2 (Deterministic Crash Controller - `crash_controller.sh` / `crash_controller.py`)**: Intercepts guest-emitted checkpoint markers (`CHECKPOINT: <name>`) in real-time from the serial console stream and instantly triggers hard power cuts (`kill -9`), QMP cold resets (`system_reset`), or clean completions with sub-millisecond latency.
- **G3 (Independent Image Inspector - `inspector.py`)**: Read-only host verification oracle that validates raw block images without importing guest kernel mount code. Validates Superblock A/B CRC-32C, generation counters, CommitRecord SHA-256, Catalog ordering, and high-water boundaries.
- **G4 (Reboot Campaign Orchestrator - `run_campaign.sh`)**: Coordinates the multi-run lifecycle, configures QEMU with direct-sync NVMe parameters, sweeps single or all checkpoints, observes recovery boots, and binds evidence records.
- **G5 (Failure-Class Reviewer - `FAILURE_CLASSES.md`)**: Formally defines the physical flash/cache flushing dynamics, commit boundaries, and oracle invariant verification matrix.

---

## 2. Workflow Lifecycle per Test Run

Every test execution follows a strict 7-stage deterministic lifecycle:

1. **Prepare Clean Image**:
   - `disk_lifecycle.sh create-instance <base> <instance>` provisions an isolated, ephemeral 64 MiB NVMe image.
   - Initial SHA-256 digest is calculated and recorded (`disk_initial_digest`).
2. **Boot Guest & Initiate Mutation**:
   - QEMU boots AArch64 UEFI guest with direct-sync NVMe:
     `-drive if=none,id=nvme0,format=raw,file=...,cache=directsync -device nvme,drive=nvme0,serial=aienos-p3-test`
   - Guest begins a transaction mutating from Generation $N$ to $N+1$.
3. **Kill / Reset at Checkpoint**:
   - `crash_controller.py watch` monitors the serial stream.
   - Upon encountering the target `CHECKPOINT: <name>` marker, the controller immediately executes a hard kill (`SIGKILL`) or cold reset (`system_reset` via QMP).
4. **Compute Resulting Image Digest**:
   - Post-crash SHA-256 digest is calculated (`resulting_image_digest`) and compared against initial state.
5. **Boot Guest Again & Observe Recovery**:
   - Guest is booted in read-only recovery mode with the post-crash NVMe image.
   - Recovery serial output is captured, verifying candidate selection and recovery status.
6. **Verify Image with Inspector**:
   - `inspector.py` executes independent verification of both Superblock slots, CommitRecord, Catalog, and block layout.
7. **Record Structured Result**:
   - All 11 required run attributes and verification verdicts are evaluated and recorded into `result.json` and aggregated into `campaign_summary.json`.

---

## 3. Persistence Checkpoint Matrix & Classification Rules

Per ADR 0015 and `FAILURE_CLASSES.md`, transactions maintain strict atomicity. The commit point is the completion of Barrier 2 (`after_final_flush`).

| # | Checkpoint Name | Description | Expected State | Classification |
|---|---|---|---|---|
| 1 | `before_first_write` | Prior to submitting any write commands | Media untouched | `OLD` (Gen 1) |
| 2 | `during_payload_writes` | During emission of payload data blocks | Uncommitted tail discarded | `OLD` (Gen 1) |
| 3 | `after_payload` | All payload extent blocks written | Uncommitted tail discarded | `OLD` (Gen 1) |
| 4 | `during_catalog` | During emission of Catalog metadata | Uncommitted catalog discarded | `OLD` (Gen 1) |
| 5 | `after_catalog` | Catalog metadata blocks completed | Uncommitted catalog discarded | `OLD` (Gen 1) |
| 6 | `during_commit_record` | During emission of CommitRecord block | Commit incomplete | `OLD` (Gen 1) |
| 7 | `before_first_flush` | Before hardware cache barrier 1 | Data volatile in drive buffer | `OLD` (Gen 1) |
| 8 | `after_first_flush` | Immediately following barrier 1 | Arena durable, Superblock unwritten | `OLD` (Gen 1) |
| 9 | `during_inactive_superblock_write`| During write of inactive Superblock slot| Inactive slot torn / CRC invalid | `OLD` (Gen 1) |
| 10 | `before_final_flush` | Superblock written, before barrier 2 | Inactive superblock dirty/volatile | `OLD` (Gen 1) |
| 11 | `after_final_flush` | Immediately following barrier 2 | **Transaction committed durably** | **`NEW` (Gen 2)** |

### Classification Invariants
- **Checkpoints 1–10**: State MUST roll back cleanly to `OLD` (Generation 1). Any advance to Generation 2 is a failure of durability semantics.
- **Checkpoint 11**: State MUST advance monotonically to `NEW` (Generation 2).
- **Illegal States**: Any corruption (`BAD_CRC` on active slot), `ConflictingRoots`, `InconsistentHistory`, mixed catalog entries, or silent modification during recovery immediately fails qualification.

---

## 4. QEMU Storage Configuration (`cache=directsync`)

The qualification runner configures QEMU NVMe drive using:
```bash
-drive if=none,id=nvme0,format=raw,file="${test_instance_path}",cache=directsync \
-device nvme,drive=nvme0,serial=aienos-p3-test
```

### Why `cache=directsync` is Mandatory:
- `cache=unsafe`: Prohibited. Caches flushes in host RAM; power cuts do not reflect durable media state.
- `cache=writeback`: Prohibited. Vulnerable to host kernel page cache dirty-page buffering and reordering across guest `SIGKILL`.
- `cache=directsync`: Uses `O_DIRECT | O_SYNC`. Bypasses host operating system page cache entirely. All guest NVMe writes and Flush commands correspond 1:1 to physical disk operations.

---

## 5. Usage Guide (`run_campaign.sh`)

### CLI Syntax
```bash
tests/p3-store-crash-qemu/run_campaign.sh [OPTIONS]
```

### Options
- `--all`: Execute full qualification sweep across all 11 checkpoints (default).
- `-c, --checkpoint <NAME>`: Execute qualification for a single designated checkpoint.
- `-a, --action <MODE>`: Crash mode: `kill` (default, `SIGKILL`), `reset` (QMP `system_reset`), `clean` (baseline), or `all` (sweep kill + reset).
- `--self-test`: Execute complete self-test of the qualification orchestrator suite.
- `--mock`: Run with synthetic ADR 0015 mutation driver for fast self-contained validation.
- `--size-mb <INT>`: NVMe disk size in MiB (default: `64`).
- `--base-image <PATH>`: Path to existing base disk image (default: generated automatically).
- `--guest-efi <PATH>`: Path to guest EFI executable.
- `-t, --timeout <SECS>`: Execution watchdog timeout (default: `30`).
- `-o, --output-dir <DIR>`: Output directory for reports and logs.
- `--keep-images`: Retain ephemeral disk instances after run (default: wiped automatically).

### Examples

#### 1. Run Complete 11-Checkpoint Campaign Sweep
```bash
tests/p3-store-crash-qemu/run_campaign.sh --all --action kill
```

#### 2. Run Single Checkpoint Test (Hard Power Cut during Catalog)
```bash
tests/p3-store-crash-qemu/run_campaign.sh -c during_catalog --action kill
```

#### 3. Run Single Checkpoint Test (Cold Reset via QMP after Payload)
```bash
tests/p3-store-crash-qemu/run_campaign.sh -c after_payload --action reset
```

#### 4. Run Full Orchestrator Self-Test
```bash
tests/p3-store-crash-qemu/run_campaign.sh --self-test
```

---

## 6. Structured Result Schema

For each run, a structured record `result.json` is generated binding all required qualification parameters:

```json
{
  "repo_sha": "ff5de9c5af6da27d0e8dc9ddefa3d7b63fbdffd3",
  "guest_artifact_digest": "04854904854677a6af846477188bda24b3b577481c9202aba506feee6738666d",
  "qemu_version": "QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18)",
  "aavmf_digest": "4a4cb7f6d8106bb2a7dd8c763fab14b1810152136fc4304e5b728f0043e84f12",
  "disk_initial_digest": "7af7a4761888aef5c8495d93de794484d9e223f27c28b28bdc4821fc4d67de2b",
  "crash_checkpoint": "during_catalog",
  "checkpoint_canonical": "during_catalog",
  "qemu_exit_mode": "kill",
  "resulting_image_digest": "fda9e4a235fb18db81f697f9b307119a36b39729aa343c39a365090b25c6b701",
  "recovered_generation": 1,
  "recovered_root": "5cef1243d3d18c6e500385e2957f25071a5ff7629770bfc3e3dd4b9d1934e5d8",
  "recovered_slot": 0,
  "classification": "OLD",
  "expected_classification": "OLD",
  "assertion_result": "PASS",
  "is_recoverable": true,
  "recovery_status": "FORWARD_PROGRESS",
  "failure_reasons": []
}
```

The aggregate campaign report `campaign_summary.json` compiles all individual test runs and reports `overall_verdict: "PASS"`.

---

## 7. Test Suites

The directory includes dedicated automated test suites:
- `test_disk_lifecycle.sh`: Validates G1 disk creation, reflink copying, hashing, device safety guards, and wiping.
- `test_crash_controller.sh`: Validates G2 checkpoint matching, SIGKILL termination, QMP reset, clean baseline, watchdog timeouts, and FIFO streams.
- `test_inspector.py`: Validates G3 host-side inspection oracle across synthetic Store v1 states and corruptions.
- `test_run_campaign.sh`: Validates G4 campaign orchestrator lifecycle, CLI flags, cold reset, evidence binding, and cleanup.
