# Recovery media boot on Machine 1: evidence

**Status: PENDING ATTENDED EXERCISE.** The recovery tooling, build path, and
evidence collector are merged and host-verified. The physical USB boot on the
DGX Spark (spark-b87b) is an operator-run, physical-access step scheduled
under TRUST-1 Gate 1. This file becomes the record of that boot.

Procedure: [docs/RECOVERY_MEDIA_MACHINE1.md](../docs/RECOVERY_MEDIA_MACHINE1.md).
Gate: [issue #17](https://github.com/aien-dev/aienos/issues/17),
TRUST-1 Gate 1 ([docs/TRUST-1-IMPLEMENTATION-PLAN.md](../docs/TRUST-1-IMPLEMENTATION-PLAN.md)).

## What is already proven (no hardware)

| Proof | Where | Result |
| --- | --- | --- |
| Zero-disk RAM boot (no internal storage dependency) | `scripts/qemu_verify_recovery_media.sh`, [gate1 receipt](gate1_zero_disk_recovery_receipt.json) | PASS (QEMU, aarch64 host) |
| Initrd ships mount / EFI repair / boot-entry restore tooling | `scripts/verify_recovery_tools.sh` | PASS (host) |
| ATLAS_RECOV and internal NVMe overwrite guards | `scripts/build_recovery_media.sh` multi-factor identity check | enforced at build |

## What the attended exercise must record

Run under `aien-proof hold --resource machine-1 --job recovery-boot-evidence`.
`scripts/collect_recovery_boot_evidence.sh` must print
`RECOVERY_BOOT_GATE: PASS`, which requires all of:

- `booted_from_removable_media`: the running root is the USB, not the NVMe.
- `secure_boot_state_recorded`: Secure Boot byte read from efivars.
- `nvme_root_mounted` + `nvme_root_is_internal`: internal NVMe root mounted.
- `esp_mounted` + `esp_write_roundtrip`: `/boot/efi` accepted a marker write.
- `efi_variables_present` + `efibootmgr_readable`: boot entries restorable.

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
| ESP write round-trip | _pending_ |
| Boot entries after restore | _pending_ |
| `RECOVERY_BOOT_GATE` | _pending_ |
