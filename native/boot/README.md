# native/boot: minimal UEFI entry stub for the C kernel core

This is the C path's UEFI entry (Lane 18). It is deliberately small:

- `image.ld` writes the PE32+ header (AArch64, EFI application, one empty
  base-relocation block) as linker data, so plain `ld` + `objcopy -O binary`
  produce `BOOTAA64.EFI`. No outside EFI libraries or objcopy EFI targets.
- `efi_entry.S` applies the image's own `R_AARCH64_RELATIVE` relocations
  (the image is linked position independent), clears BSS and calls `efi_main`.
- `efi.h` holds the UEFI types the stub needs, written from the UEFI spec.
- `efi_main.c` prints the pre-exit report on ConOut (`report_kind: pre_exit`,
  `aienos_commit: <full commit>` from the build-time `AIENOS_COMMIT`), finds
  the ACPI 2.0 RSDP and the SPCR UART, takes the final memory map and calls
  `ExitBootServices`, retrying when the map key goes stale, then jumps to
  `ck_kernel_entry` with a `struct ck_handoff` (`handoff.h`): memory-map
  copy, RSDP, firmware EL, firmware TTBR0/SCTLR, counter, commit.

**A/B slots live in a separate loader, `slot_loader.c` -> `SLOTLDR.EFI` (P11
cut 2a, gate N7, QEMU only; owner decision 2026-10-12: narrowly scoped to
signed A/B image selection, boot-success tracking and rollback).** It sits in
front of this stub as the boot volume's `EFI/BOOT/BOOTAA64.EFI`, reads the
slots partition (`slot_format.h`), verifies both slots against owner keys
baked in at build time, applies `slot_select.c` (bounded candidate tries,
generation floor, never a boot loop), commits a candidate try before the jump,
and chain-loads the chosen image (this stub + kernel, unchanged and
byte-identical) with `LoadImage` + `StartImage`. Both slots invalid: it prints
`slot_loader: recovery_required (...)`, then starts the known-good recovery
image from its own volume (`\EFI\AIENOS\RECOVERY.EFI` + `RECOVERY.MAN`,
verified with the same keys; P11 cut 4, `docs/NATIVE_IMAGE_SLOTS.md` section
10) or, when there is none or it is refused, returns to the firmware. It never
touches UEFI variables, runtime services or `ExitBootServices`. Build:
`make -C native/kernel slot-loader CK_SLOT_KEYS=<file>` (or the TEST-ONLY
`CK_TEST_SLOT_KEY=1`, refused with `CK_HARDWARE_STAGING`); gate
`scripts/qemu_ck_slot_loader_test.sh`; `docs/NATIVE_IMAGE_SLOTS.md`. This stub
itself still has no slot logic, so the paragraph below stays true for it.

**Parked, not here:** signature checks, BootNext staging, rollback and the
boot-report file. The Rust `aienos-boot` crate has BootNext staging and a QEMU
rollback test but no A/B slot selection (ADR 0024 Q3); it is frozen and
parked for the C path; this stub boots the kernel linked into the same image
and nothing else. Rollback needs no loader code: the firmware's one-time BootNext
starts this image once and the unchanged BootOrder brings the Default back;
`scripts/qemu_ck_rollback_test.sh` (CK gate M0_ROLLBACK) checks that in QEMU
with this image as the candidate.

Build and test from `native/kernel` (see its README). QEMU qualifies nothing
physical.

The handoff record (`handoff.h`, magic `CHANDOF1`) is specified, with what is
frozen, what the kernel must refuse and how rollback works without A/B slots,
in `docs/BOOT_HANDOFF_CONTRACT.md` (SPEC, NOT_RUN; ADR 0024 Q3).
