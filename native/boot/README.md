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

**Parked, not here:** signature checks, A/B slots, BootNext, rollback and the
boot-report file. That loader exists in the Rust `aienos-boot` crate and is
parked for the C path; this stub boots the kernel linked into the same image
and nothing else.

Build and test from `native/kernel` (see its README). QEMU qualifies nothing
physical.

The handoff record (`handoff.h`, magic `CHANDOF1`) is specified, with what is
frozen, what the kernel must refuse and how rollback works without A/B slots,
in `docs/BOOT_HANDOFF_CONTRACT.md` (SPEC, NOT_RUN; ADR 0024 Q3).
