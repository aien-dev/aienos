# M0 Native-Boot Rollback Evidence Audit

## Executive Summary & Gate Verdict

This document audits all historical and current physical evidence from Machine 1 (NVIDIA DGX Spark, `spark-b87b`) regarding the **M0 Native-Boot Rollback Gate**.

### Core Questions

#### A. Does existing evidence already satisfy the M0 rollback gate?
**NO.** Existing evidence is **INSUFFICIENT** to close the M0 rollback gate on physical hardware. While individual mechanisms (such as UEFI `BootNext` consumption and fallback to GRUB/Linux) were observed across separate historical boots, the full set of mandatory safety and rollback invariants has never been satisfied simultaneously under the required security baseline.

#### B. What are the exact missing assertions?
1. **Secure Boot Unchanged & Enabled:** The M2 native boot (`evidence/m2_first_boot_2026-09-24.md`) was performed with **Secure Boot explicitly disabled** in firmware. The recovery USB boot (`evidence/recovery_boot_machine1.md`) ran with Secure Boot enabled, but it booted an Ubuntu Linux recovery image, not native AIENOS.
2. **TPM PCR 7 & Sealed Storage Invariant:** Disabling Secure Boot for the M2 boot mutated TPM PCR 7, preventing the unsealing of the LUKS/storage keys for `atlas-private-storage` and `atlas-forgejo-storage` and triggering a service restart storm (`evidence/machine1_core_baseline_2026-09-24.md`). A valid rollback test must prove that TPM-sealed state remains unperturbed before, during, and after candidate execution.
3. **Hardware Trust Chain Boundary (`HARDWARE_QUALIFICATION_BLOCKED_BY_TRUST_CHAIN`):** Machine 1 currently has Secure Boot enabled with production firmware keys (Microsoft / Canonical). The native AIENOS boot image (`aienos-handoff.efi`) is not signed by an enrolled key. Attempting to boot it directly under Secure Boot fails immediately with `Secure Boot Violation` (`evidence/gate1_machine1_selftest_2026-09-24.md`). Hardware qualification of native AIENOS is therefore formally **blocked by trust chain**.
4. **Failure & Fault Branch Coverage:** The historical M2 native boot tested only a single cooperative countdown-and-reset path. It did not test candidate crash/panic, CPU fault, runaway timeout, or corrupted/untrusted binary fallback.
5. **Exact BootOrder Invariance:** On the M2 native boot, firmware appended `Boot0004` (USB stick) to `BootOrder` (`0001,0003` became `0001,0003,0004`). While the relative order of default entries was preserved, strict bit-for-bit invariance was not asserted.
6. **Cryptographic Root/ESP Identity Pre/Post Verification:** Historical runs lacked unified cryptographic verification asserting that internal root UUID (`d27bfd26-ff30-400e-9eca-9cdf73de9406`), ESP UUID (`9DA2-3597`), and filesystem mount options remained identical before staging and after return.
7. **Post-Consumption Re-execution Immunity:** No test demonstrated that subsequent host reboots after the one-time boot attempt continue to boot the default OS without entering a loop or re-invoking the candidate.

---

## Detailed Audit of Existing Evidence

### 1. M2 First Native Boot (`evidence/m2_first_boot_2026-09-24.md`)
- **Staging:** Performed via `scripts/stage_one_time_boot.sh`. Staged `aienos-handoff.efi` (`79505373088d2464b82181c06f07e18e20e4e9b2b55dbc9fc46e3f0a2e2e3ada`) into `\EFI\AIENOS\aienos-handoff.efi`, created boot entry `Boot0000`, set `BootNext = 0000`.
- **Pre-boot State:** `BootCurrent: 0001`, `BootOrder: 0001,0003`, `linux_kernel: 7.0.0-1019-nvidia`.
- **Execution:** Machine left firmware, entered AIENOS at EL2, validated memory map, wrote `AienosBootReportV1` NVRAM variable (`kernel: alive`), counted down 30 seconds, and executed a PSCI cold reset.
- **Return:** Machine booted back into Linux. `BootCurrent: 0001`, `BootNext` consumed, `root: rw`.
- **Defects & Invalidation:**
  - Secure Boot was manually turned **OFF** prior to the run (`docs/NATIVE_BOOT_ONE_TIME.md`, line 50).
  - PCR 7 changed, breaking TPM secret unsealing (`machine1_core_baseline_2026-09-24.md`).
  - `BootOrder` was altered by firmware: `0001,0003,0004` (firmware added USB entry).
  - Pre-exit report file `\EFI\AIENOS\BOOTREPORT.TXT` failed to write to disk.

### 2. Machine 1 Baseline & Restart Storm Resolution (`evidence/machine1_core_baseline_2026-09-24.md`)
- Following the M2 boot, Secure Boot was re-enabled to restore TPM PCR 7 stability.
- Documented that turning Secure Boot off is an unsafe operation on Machine 1 because secrets are sealed to PCR 7.
- Established the doctrine: **Secure Boot must remain ON at all times during native boot testing.**

### 3. Recovery Media Attended Boot (`evidence/recovery_boot_machine1.md`)
- **Staging & Boot:** `Boot0004` (USB recovery stick) was booted via `efibootmgr -n 0004` with Secure Boot **ON**.
- **Execution:** Booted Ubuntu shim -> signed GRUB -> signed kernel (`7.0.0-1019-nvidia`) -> RAM initrd. Inspected root (`UUID="d27bfd26-ff30-400e-9eca-9cdf73de9406"`) and ESP (`UUID="9DA2-3597"`) read-only.
- **Return:** Returned to normal Ubuntu boot (`BootCurrent: 0001`, `BootOrder: 0001,0003,0004`).
- **Defects & Invalidation:**
  - This verified the recovery media boot path, **not** an AIENOS native candidate.
  - The receipt omitted post-return `mokutil --sb-state` and post-return `efibootmgr` captures.

### 4. TRUST-1 Gate 1 Self-Test (`evidence/gate1_machine1_selftest_2026-09-24.md`)
- Tested one-time reboot into recovery media via `efibootmgr -n 0004`.
- **Finding:** A previous attempt to boot a direct entry `Boot0000 "AIENOS"` pointing directly to an unsigned kernel binary failed with **`Secure Boot Violation`**.
- Reaffirmed that firmware rejects unsigned EFI binaries when Secure Boot is ON.

---

## Evidence Audit Matrix

| Assertion # | Required Rollback Invariant | Existing Evidence | Proven? | Missing Evidence / Failure Mode | Required Next Action |
|:---:|:---|:---|:---:|:---|:---|
| **1** | Default/Linux boot state captured before candidate boot | `m2_first_boot_2026-09-24.md`, `STAGED.TXT` | **PROVEN** | None. Baseline capture is established. | Maintain pre-boot capture format in automated tools. |
| **2** | One-time candidate selected without replacing default BootOrder | `m2_first_boot_2026-09-24.md`, `gate1_machine1_selftest_2026-09-24.md` | **PROVEN** | None. `efibootmgr --bootnext` creates one-time boot without modifying `BootOrder`. | Standardize in rollback contract. |
| **3** | AIENOS actually gains native control | `m2_first_boot_2026-09-24.md` (`kernel: alive`, EL2) | **PARTIAL** | Only proven with Secure Boot OFF. Unproven with Secure Boot ON. | Requires signed binary or owner trust enrollment. |
| **4** | Failure, fault, timeout, or exit does not create a boot loop | `m2_first_boot_2026-09-24.md` (clean exit only) | **UNPROVEN** | Fault, hang/timeout, and invalid image branches were never tested on hardware. | Prove all failure branches in QEMU harness. |
| **5** | One-time selection (`BootNext`) is consumed | `m2_first_boot_2026-09-24.md`, `recovery_boot_machine1.md` | **PROVEN** | None. Firmware deletes `BootNext` upon boot. | Re-verify in automated test harness. |
| **6** | Machine returns to default Linux boot path | `m2_first_boot_2026-09-24.md` (`BootCurrent: 0001`) | **PROVEN** | None. Return to `BootCurrent: 0001` occurred. | Re-verify in automated test harness. |
| **7** | Permanent `BootOrder` remains unchanged | `m2_first_boot_2026-09-24.md` | **PARTIAL** | Firmware added `0004` (USB stick). `0001,0003` became `0001,0003,0004`. | Enforce strict comparison ignoring or isolating hotplug devices. |
| **8** | Secure Boot state remains unchanged (and ON) | `m2_first_boot_2026-09-24.md` | **FAILED** | Secure Boot was explicitly turned **OFF** for M2 boot. | Mandatory Secure Boot ON invariant; block hardware boot until signed. |
| **9** | Linux root and ESP state remain intact | `m2_first_boot_2026-09-24.md`, `recovery_boot_machine1.md` | **PARTIAL** | Checked `root: rw`, but UUIDs, partition tables, and mount points were not diffed. | Automated pre/post evidence verifier checking exact UUIDs. |
| **10** | No TPM, firmware trust, or key mutation required | `machine1_core_baseline_2026-09-24.md` | **FAILED** | Secure Boot disable altered PCR 7, breaking storage unseal. | Forbid Secure Boot mutation; maintain PCR 7 integrity. |
| **11** | Evidence is independently inspectable | `m2_first_boot_2026-09-24.md`, `evidence/*.md` | **PROVEN** | Ledger payloads and markdown receipts exist in git. | Package automated evidence verifier CLI. |

---

## Formal Status: Hardware Qualification Blocked

Because the native AIENOS binary (`aienos-handoff.efi`) is not signed by a key trusted by Machine 1's UEFI database (`db`), and because the hard safety rules prohibit disabling Secure Boot, enrolling keys into production firmware, or mutating TPM configuration:

```text
HARDWARE_QUALIFICATION_BLOCKED_BY_TRUST_CHAIN
```

### Action Plan
1. **Emulation Proof (M0 Rollback Gate in QEMU):** All 6 rollback failure branches (normal exit, panic/fault, hang/timeout, rejected/corrupt image, absent candidate, and repeated post-consumption reboot) will be proven deterministically in QEMU using disposable variable storage (`AAVMF_VARS.fd`).
2. **Safe Operational Runbook:** Update `docs/NATIVE_BOOT_ONE_TIME.md` to permanently retire the obsolete Secure-Boot-off procedure and enforce the trust boundary.
3. **Automated Verifier:** Deliver a host-side verifier script that validates pre- and post-boot records and yields `PASS`, `FAIL`, `BLOCKED`, or `INCOMP`.
