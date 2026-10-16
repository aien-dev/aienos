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
`slot_loader: recovery_required (...)` and returns to the firmware. It never
touches UEFI variables, runtime services or `ExitBootServices`. Build:
`make -C native/kernel slot-loader CK_SLOT_KEYS=<file>` (or the TEST-ONLY
`CK_TEST_SLOT_KEY=1`, refused with `CK_HARDWARE_STAGING`); gate
`scripts/qemu_ck_slot_loader_test.sh`; `docs/NATIVE_IMAGE_SLOTS.md`. This stub
itself still has no slot logic, so the paragraph below stays true for it.

**AIENOS-PI5-BOOT-0 diagnostic, `diag_main.c` -> `PI5DIAG.EFI`:** a separate,
kernel-free UEFI application for the first Raspberry Pi 5 firmware boot. It
prints the firmware vendor and revisions, the exception level, a memory map
summary and every ConfigurationTable GUID (ACPI 1.0/2.0, SMBIOS, SMBIOS3, Device
Tree b1b621d5-f19c-41a5-830b-d9152c69aae0, per edk2 `Guid/Fdt.h`) to ConOut, writes
the same text to `\EFI\AIENOS\PI5BOOT0.TXT` on the volume it was loaded from.
AIENOS-PI5-ACPI-0 added: every table the XSDT names, plus the DSDT from the FADT,
is copied byte for byte to `\EFI\AIENOS\ACPI\<SIG>[n].BIN` (the k-th repeat of a
signature gets the suffix k) with one `acpi_table:` report line each (length,
address, checksum). It arms a 180 s firmware watchdog, waits about 5 s at the end
and cold-resets through `ResetSystem`, the only runtime service it calls, so a
one-shot tryboot run on the Pi falls back to the normal OS by itself. It never
calls `ExitBootServices`.
Build: `make -C native/kernel pi5-diag` (output `PI5DIAG.EFI`, copy to the card as
`EFI/BOOT/BOOTAA64.EFI`); QEMU test: `scripts/qemu_ck_pi5_diag_test.sh`
(`AIENOS_PI5_DIAG`; an emulator, nothing about a Pi 5 is qualified by it).

**AIENOS-IMAC-BOOT-0 diagnostic, the same `diag_main.c` built for x86_64 ->
`IMACDIAG.EFI`:** the first AIENOS code for an x86_64 machine, a 2017 iMac (Intel
Core i7, AMD Radeon Pro, Fusion Drive; no T2 chip, so its firmware starts unsigned
images). Same report and ACPI copies as the Pi diagnostic, plus `diag_x86.c`:
CPUID identity, features, topology and CPU mode; SMBIOS type 0/1/2 identity (no
serial numbers); every PCI function through configuration ports 0xCF8/0xCFC (reads
only); every GOP mode; every whole-disk Block I/O device. It selects text mode
through Apple's console-control protocol first (ConOut is invisible on a Mac
otherwise), writes `\EFI\AIENOS\IMACBOOT.TXT`, holds the screen ~30 s and powers off
through `ResetSystem(EfiResetShutdown)`. x86_64 pieces: `efi_entry_x86_64.S`
(R_X86_64_RELATIVE relocations, Microsoft x64 entry), `image_x86_64.ld` (Machine
0x8664), compiled `-mabi=ms` so `efi.h` stays unannotated. Build:
`make -C native/kernel imac-diag` (output `IMACDIAG.EFI`, copy to a FAT stick as
`EFI/BOOT/BOOTX64.EFI`); QEMU test: `scripts/qemu_ck_imac_diag_test.sh`
(`AIENOS_IMAC_DIAG`, q35 + OVMF; an emulator, nothing about the iMac is qualified by it).

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
