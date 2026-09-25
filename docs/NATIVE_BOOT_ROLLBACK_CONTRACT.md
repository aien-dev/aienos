# AIENOS Native-Boot Rollback Contract

## 1. Scope & Purpose

This contract specifies the deterministic lifecycle, state machine, and safety invariants for one-time native boots of AIENOS candidates on UEFI platforms (including physical NVIDIA DGX Spark / Machine 1 and QEMU AArch64 reference emulators).

---

## 2. Core Invariant

> **A candidate may consume exactly one boot attempt. It may never promote itself into the persistent default boot path.**

Under no circumstances—whether normal completion, kernel panic, CPU exception, infinite loop/timeout, binary rejection, or power loss—may the platform enter an unrecoverable boot loop, and under no circumstances may the candidate modify the persistent boot priority of the system.

---

## 3. Subsystem Separation of Concerns

1. **Permanent Default Boot Configuration:**
   - The primary operating system (e.g. Ubuntu Linux under GRUB/shim on Machine 1, or default reference OS in QEMU) is represented by persistent boot variable `Boot0001` (or existing default `BootCurrent`).
   - The UEFI `BootOrder` variable lists default entries in priority order (e.g. `0001,0003`).
   - The default boot configuration is immutable with respect to candidate execution.
   - Secure Boot state remains enabled (`SecureBoot=1`).
   - TPM PCR policies and sealed volume secrets remain intact.

2. **One-Time Candidate Selection:**
   - Candidates are staged into dedicated, non-default paths on the EFI System Partition (e.g. `\EFI\AIENOS\aienos-candidate.efi`).
   - A non-default boot entry is allocated (e.g. `Boot0000`).
   - The candidate is selected **strictly** through the UEFI `BootNext` variable (`BootNext = 0000`).
   - `BootOrder` is **never modified** when staging a candidate.

3. **Candidate Consumption by Firmware:**
   - Per UEFI Specification §3.1.1, the platform firmware must consume (delete) `BootNext` prior to transferring control to the candidate binary.
   - Once firmware starts the candidate, `BootNext` no longer exists in NVRAM.

4. **Candidate Execution Termination Modes:**
   - **Orderly Termination:** The candidate finishes execution, prints diagnostic reports to screen/UART, and initiates cold system reset (via PSCI or UEFI Runtime Services `ResetSystem(ResetCold)`).
   - **Panic / CPU Fault:** Upon encountering an exception, panic, or unhandled trap, the exception vector records fault registers (ESR, ELR, FAR, SPSR) to diagnostics and triggers cold reset.
   - **Hang / Timeout:** If the candidate hangs or loops, an external hardware/emulator watchdog or an operator power-cycle triggers cold reset.
   - **Firmware Rejection / Malformed Image:** If the image PE header is invalid or fails signature checks, firmware refuses execution and drops to the next option in `BootOrder` or returns to BDS.
   - **Absent Image:** If the file referenced by `Boot0000` is missing, firmware drops to `BootOrder`.

5. **Fallback to Default Boot:**
   - Because `BootNext` was consumed by firmware before or during the candidate launch, any subsequent reset or firmware boot evaluation encounters an empty `BootNext`.
   - Firmware evaluates `BootOrder` and immediately launches the permanent default bootloader (`Boot0001`).

6. **Out-of-Band Recovery Fallback:**
   - If the internal storage or default bootloader is corrupted by external factors, the dedicated, proved recovery USB media (`Boot0004` / `AIENOSRECOV`) remains bootable via the firmware interactive boot menu (`F11`/`BDS`), operating 100% in RAM with zero hard disk dependencies.

---

## 4. Formal Finite State Machine (FSM)

```
  +-------------------------------------------------------------+
  |                        DefaultReady                         |
  | (Linux running, BootOrder=[0001,...], BootNext unset)       |
  +-------------------------------------------------------------+
                                 |
                                 | [Operator stages candidate]
                                 v
  +-------------------------------------------------------------+
  |                       CandidateStaged                       |
  | (Image on ESP, Boot0000 created, BootOrder UNTOUCHED)       |
  +-------------------------------------------------------------+
                                 |
                                 | [efibootmgr --bootnext 0000]
                                 v
  +-------------------------------------------------------------+
  |                    CandidateSelectedOnce                    |
  | (BootNext=0000, BootOrder=[0001,...])                       |
  +-------------------------------------------------------------+
                                 |
                                 | [System reboot]
                                 v
        Firmware consumes & deletes BootNext in NVRAM
                                 |
         +-----------------------+-----------------------+
         |                                               |
         | [Valid binary]                                | [Corrupt/Missing/Rejected]
         v                                               v
  +----------------------+                     +-------------------+
  |   CandidateRunning   |                     | CandidateRejected |
  | (EL2/EL1, native)    |                     | (BDS fails load)  |
  +----------------------+                     +-------------------+
         |                                               |
         +--------------------+                          |
         |                    |                          |
 [Normal Exit]        [Fault/Panic/Timeout]              |
         |                    |                          |
         v                    v                          v
  +--------------+    +----------------+                 |
  | ResetOrExit  |    | Watchdog/Reset |                 |
  +--------------+    +----------------+                 |
         |                    |                          |
         +--------------------+--------------------------+
                                 |
                                 | [System cold reset / fallback]
                                 v
                 Firmware evaluates BootOrder (BootNext=NONE)
                                 |
                                 v
  +-------------------------------------------------------------+
  |                       DefaultReturned                       |
  | (Linux running, BootCurrent=0001, BootOrder unchanged)      |
  +-------------------------------------------------------------+
                                 |
                                 | [Subsequent reboot(s)]
                                 v
  +-------------------------------------------------------------+
  |                        DefaultReady                         |
  | (System stays on Linux permanently; no candidate recurrence)|
  +-------------------------------------------------------------+
```

---

## 5. Transition Rules & Invariants

1. **Deterministic Return Invariant:**
   $\forall s \in \{\text{NormalExit}, \text{Fault}, \text{Timeout}, \text{Rejected}, \text{Missing}\}, \quad \text{NextBoot}(s) = \text{DefaultBoot}$

2. **Non-Promotion Invariant:**
   Under no execution path may `Boot0000` be inserted into `BootOrder`.
   $\text{BootOrder}_{\text{post}} = \text{BootOrder}_{\text{pre}}$

3. **Single-Attempt Invariant:**
   $\text{BootNext}_{\text{post}} = \emptyset$

4. **No Autonomous Staging:**
   No software component running within `CandidateRunning` or `DefaultReturned` may set `BootNext` or stage another candidate without explicit, authenticated operator dispatch.

5. **Storage & Trust Isolation:**
   - Candidate execution must not mutate internal Linux root partition UUIDs or filesystem structures.
   - Candidate execution must not alter UEFI Secure Boot configuration or TPM NVRAM allocations.
