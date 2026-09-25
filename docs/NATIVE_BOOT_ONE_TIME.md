# Machine 1 Native Boot Qualification Procedure: Attended, One-Time, Secure Boot ON

This document defines the safe, operator-attended qualification procedure for one-time native candidate boots of AIENOS on NVIDIA DGX Spark ("Machine 1", `spark-b87b`).

---

## 1. Current Qualification Status

```text
HARDWARE_QUALIFICATION_BLOCKED_BY_TRUST_CHAIN
```

> [!CAUTION]
> **DO NOT DISABLE SECURE BOOT.**
> On Machine 1, turning Secure Boot off alters TPM PCR 7. On the historical 2026-09-24 first-boot test, changing PCR 7 prevented the TPM from unsealing the volume encryption keys for `atlas-private-storage` and `atlas-forgejo-storage`, locking the filesystem and causing severe service restart loops (`evidence/machine1_core_baseline_2026-09-24.md`). Secure Boot was restored and must remain **ENABLED** at all times.
>
> The native AIENOS boot images (`aienos-handoff.efi`, `aienos-boot.efi`) are not currently signed by a key enrolled in Machine 1's UEFI database (`db`). Direct execution under Secure Boot will fail with `Secure Boot Violation` (`evidence/gate1_machine1_selftest_2026-09-24.md`).
>
> Physical hardware native boots remain **BLOCKED** until the owner-controlled boot trust chain (ADR 0007 / TRUST-1 implementation) is enrolled in firmware. **Do not attempt to bypass this boundary by turning Secure Boot off.** All rollback semantics must be validated in QEMU (`scripts/qemu_native_rollback_test.sh`).

---

## 2. Hard Invariants & Safety Constraints

1. **Secure Boot Enforced:** Machine 1 must report `SecureBoot enabled` (`/sys/firmware/efi/efivars/SecureBoot-*` byte 4 == 1). Any tool or procedure attempting to disable Secure Boot fails closed.
2. **Permanent BootOrder Immutable:** `BootOrder` must not be modified. Linux (Ubuntu GRUB/shim, `Boot0001`) remains the permanent, unchallengeable default.
3. **One-Time Staging Only:** Candidates are invoked strictly via UEFI `BootNext`. Firmware deletes `BootNext` upon boot.
4. **Zero Persistent Storage Mutation:** Candidate execution must not write to Linux root (`/dev/nvme0n1p2`) or alter the EFI System Partition (`/dev/nvme0n1p1`) outside of the staging scratch directory `\EFI\AIENOS`.
5. **Attended Execution Only:** No autonomous or unattended physical hardware reboots are permitted. Operator must be present at physical console with recovery media attached.

---

## 3. Preparation & Pre-Flight Verification

Ensure the operator is present at the physical machine with:
1. **Recovery Media:** Dedicated `AIENOSRECOV` USB stick inserted into Machine 1 (`Boot0004`), tested and proved per `docs/RECOVERY_MEDIA_MACHINE1.md`.
2. **Physical Display & Keyboard:** Attached directly to DGX Spark console.
3. **Service Quiescence:** Non-core services stopped per `evidence/machine1_core_baseline_2026-09-24.md`.

---

## 4. Execution Workflow (When Trust Chain is Enrolled)

### Step 1: Pre-Boot Baseline Capture
Capture the complete pre-boot state into `evidence/pre_boot_capture.json`:
```bash
sudo scripts/verify_native_rollback.sh --capture-pre evidence/pre_boot_capture.json
```
This records:
- Secure Boot status (`enabled`)
- Active and permanent boot configuration (`BootCurrent`, `BootOrder`, no `BootNext`)
- Partition UUIDs:
  - Root: `d27bfd26-ff30-400e-9eca-9cdf73de9406` (ext4, mounted at `/`)
  - ESP: `9DA2-3597` (vfat, mounted at `/boot/efi`)
- Kernel release (`uname -r`)

### Step 2: One-Time Candidate Staging
Under lease hold (`aien-proof hold --resource machine-1`):
```bash
# Verify working tree is clean and map to exact commit
commit=$(git rev-parse HEAD)

# Build signed native candidate (requires owner signing key)
scripts/sign_efi_binary.sh target/aarch64-unknown-uefi/release/aienos-handoff.efi

# Stage image to ESP and set BootNext
sudo bash scripts/stage_one_time_boot.sh --apply
```
The staging script:
1. Copies the authenticated binary to `/boot/efi/EFI/AIENOS/aienos-handoff.efi`.
2. Verifies that `BootOrder` is preserved unchanged.
3. Creates/verifies non-default boot entry `Boot0000 "AIENOS handoff (one-time)"`.
4. Sets `BootNext = 0000`.

### Step 3: Candidate Boot & Observation
1. Reboot the machine:
   ```bash
   sudo reboot
   ```
2. **Observe Physical Screen:**
   - Firmware starts and evaluates `BootNext`.
   - If firmware accepts signature: AIENOS banner, memory map validation, `kernel: alive` on screen.
   - Candidate counts down 30 seconds and calls cold reset via PSCI.
   - **If firmware reports `Secure Boot Violation`:** This is an expected STOP condition if keys are missing. Do not bypass. The machine will fall back to `BootOrder` (Linux).
3. **If Machine Hangs:**
   - Wait 60 seconds.
   - Power-cycle using the chassis power button.
   - Because firmware consumed `BootNext` prior to launching the image, the reset will boot Linux (`BootOrder[0] = 0001`).

### Step 4: Out-of-Band Fallback (If Linux Fails to Boot)
If Linux does not automatically load:
1. Press `F11` (or firmware BBS hotkey) during startup.
2. Select `Boot0004` (`AIENOSRECOV` USB recovery stick).
3. In the recovery environment, verify root and ESP integrity read-only per `docs/RECOVERY_MEDIA_MACHINE1.md`.

### Step 5: Post-Return Capture & Automated Verification
Once returned to Linux:
```bash
sudo scripts/verify_native_rollback.sh \
    --pre evidence/pre_boot_capture.json \
    --post evidence/post_boot_capture.json \
    --verify
```
The automated verifier evaluates all 10 invariants:
- Secure Boot state: unchanged (`enabled`)
- `BootOrder`: identical to pre-boot
- `BootCurrent`: returns to `0001` (Linux)
- `BootNext`: consumed / empty
- Root partition UUID & mount (`/`, `rw`): unchanged
- ESP partition UUID & mount (`/boot/efi`, `rw`): unchanged
- No boot loop created
