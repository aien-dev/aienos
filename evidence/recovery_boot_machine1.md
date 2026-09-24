# Recovery media boot on Machine 1: evidence

**Status: PENDING ATTENDED EXERCISE.** The repair-tool additions to the
recovery initrd, the tooling check, and the read-only evidence collector are
merged and host-verified (QEMU, no real devices). No hardware boot with
these tools has happened yet. The physical USB boot on the DGX Spark
(spark-b87b) is an operator-run, physical-access step scheduled under
TRUST-1 Gate 1. **The `AIENOSRECOV` stick must be rebuilt with
`scripts/build_recovery_media.sh` first** -- the stick as last written (#53)
predates the repair tools this record is about. This file becomes the
record of that boot; nothing below is a claim that it already happened.

Procedure: [docs/RECOVERY_MEDIA_MACHINE1.md](../docs/RECOVERY_MEDIA_MACHINE1.md).
Gate: [issue #17](https://github.com/aien-dev/aienos/issues/17),
TRUST-1 Gate 1 ([docs/TRUST-1-IMPLEMENTATION-PLAN.md](../docs/TRUST-1-IMPLEMENTATION-PLAN.md)).

## What is already proven (no hardware)

| Proof | Where | Result |
| --- | --- | --- |
| Zero-disk RAM boot (no internal storage dependency) | `scripts/qemu_verify_recovery_media.sh` | PASS (QEMU, aarch64 host) |
| Initrd ships mount / EFI repair / boot-entry restore tooling | `scripts/verify_recovery_tools.sh` | PASS (host, static check) |
| Recovery stick boots on Machine 1 with Secure Boot on, returns unattended (previous initrd, without repair tools) | [gate1_machine1_selftest_2026-09-24.md](gate1_machine1_selftest_2026-09-24.md) | PASS on hardware (#53) |
| Internal NVMe / active-mount overwrite guards | `scripts/build_recovery_media.sh` identity checks | enforced at build (unchanged by this PR) |

## What the attended exercise must record

Run under `aien-proof hold --resource machine-1 --job recovery-boot-evidence`.
`scripts/collect_recovery_boot_evidence.sh` must print
`RECOVERY_BOOT_GATE: PASS`, which requires all of:

- `booted_from_removable_media`: the running root is the USB, not the NVMe.
- `secure_boot_state_recorded`: Secure Boot byte read from efivars.
- `nvme_root_mounted` + `nvme_root_is_internal`: internal NVMe root mounted
  by the operator from the recovery shell (Step 4.1 of the runbook).
- `esp_mounted` + `esp_fallback_bootloader_present`: `/boot/efi` mounted and
  the shim/GRUB fallback chain confirmed present (Step 4.2).
- `efi_variables_present` + `efibootmgr_readable`: boot entries restorable
  (Step 4.3).

The collector is read-only; it never writes to the ESP, the NVMe root, or
BootOrder.

## Boot record (fill in after the exercise)

| Item | Value |
| --- | --- |
| Date (UTC) | _pending_ |
| Operator | _pending_ |
| aien-proof ledger events | _pending_ |
| Media device | _pending_ |
| Kernel booted | _pending_ |
| Secure Boot during boot | _pending_ |
| NVMe root device mounted | _pending_ |
| `/boot/efi` fallback bootloader present | _pending_ |
| Boot entries after inspection/restore | _pending_ |
| `RECOVERY_BOOT_GATE` | _pending_ |
