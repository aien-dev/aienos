# native/kernel: AIENOS C kernel core (Lane 18)

The first AIENOS kernel written in C for AArch64. It boots in QEMU through
UEFI (AAVMF) the way the Rust kernel does and prints the same observables.
QEMU qualifies nothing physical: a PASS here says nothing about real hardware.

## Layout

| Path | What |
| --- | --- |
| `include/ck.h` | Frozen contract for stage code (devices, security, store). Lane 18 core added only `ck_irq_register`, `ck_irq_enable`, `ck_irq_cpu_enable`. |
| `arch/` | Vectors, EL2 -> EL1h entry (ADR 0009), recoverable probe, exception and IRQ dispatch, GICv3, EL1 physical timer. |
| `mm/` | Frame allocator (UEFI map), 4 KiB-granule page-table builder, heap, the kernel address space (`mmu.c`). |
| `core/` | Console, printf, ACPI, reports/panic/PSCI reset, M3 (threads, scheduler, EL0, capabilities, IPC), `kmain.c`. |
| `tests/` | Host unit tests. |
| `../boot/` | Minimal UEFI entry stub (one image with the kernel). |

## Build and test

    make -C native/kernel            # target/native-kernel/BOOTAA64.EFI
    make -C native/kernel test       # host tests, ends CK_CORE_HOST: PASS
    make -C native/kernel sanitize   # same under ASan + UBSan
    make -C native/kernel full       # + stages: target/native-kernel/full/BOOTAA64.EFI
    make -C native/kernel stage-test # stage host tests (also stage-sanitize, stage-free)
    scripts/qemu_ck_boot_test.sh     # QEMU boot of the core-only image, ends AIENOS_CK_M1: PASS
    scripts/qemu_ck_store_test.sh    # QEMU NVMe + Store gate (full image, QEMU-only
                                     # CK_QEMU_UNSAFE_DMA=1 build), ends AIENOS_CK_M4_NVME,
                                     # AIENOS_CK_M4_STORE, AIENOS_CK_ARGUS1_REVOKE

Toolchain: gcc, binutils (ld, objcopy, nm, readelf), make, shell. On a
non-aarch64 host the Makefile uses the `aarch64-linux-gnu-` prefix.
Output lands in `<repo>/target/native-kernel` (ignored by git).

## Owner provisioning (hardware staging image)

The default and QEMU images use the labelled TEST Store keys
(`ck_store_test_keys`, public label, `M5_ID_TEST`), the TEST store uuid and
the TEST ARGUS machine id (0xA1; the default image prints `argus: TEST machine id 0xA1 ...` on the serial console). The hardware staging image never embeds any
of them:

    make -C native/kernel full CK_HARDWARE_STAGING=1 \
        CK_OWNER_PUBKEYS=<owner public keys file> CK_MACHINE_ID=<machine id file>
    # -> target/native-kernel/full-hardware-staging/BOOTAA64.EFI

- Without both files the Makefile stops with `CK_HARDWARE_STAGING refuses the
  TEST Store keys and TEST machine id`. `svc/store_boot.c` and
  `svc/security.c` also `#error` in a `CK_HARDWARE_STAGING` build without the
  generated header, and the linked image is checked (Makefile `owner_check`)
  to carry no TEST Store label, uuid, TEST print line or TEST key symbol.
- The files hold PUBLIC material only, as text lines `<name> <hex>` (`#`
  comments; each name exactly once). Owner file:
  `owner_root_ed25519 <64 hex>` (the Gate 3 Owner Root public key). Machine
  file: `machine_id <64 hex>` (ARGUS machine id, 32 bytes) and
  `store_uuid <32 hex>` (boot Store uuid). `tools/ck_owner_gen.c` checks them
  and writes `ck_owner_prov.h` into the OUT directory (never committed). It
  refuses the RFC 8032 TEST 1/2/3 public keys, the TEST machine id, the TEST
  store uuid, all-equal bytes, wrong lengths, non-hex, duplicates and unknown
  names. Real owner files are never committed.
- What the image uses: the machine id becomes the ARGUS machine id, the store
  uuid the boot Store uuid, and the boot log prints a SHA-256 fingerprint of
  the owner root key. Nothing in the kernel verifies with the owner root key
  yet.
- **Production Store keys are BLOCKED_OPERATOR.** Store keys derive from
  K_vol (ADR 0017), which is secret and cannot come from public material.
  `ck_store_production_keys` always refuses (`CK_SB_E_BLOCKED_OPERATOR`), so
  the hardware staging Store stage prints `store: REFUSED proof=keyed
  step="production Store key source"` and neither reads nor formats the disk.
  To unblock it the operator must provide, through the TRUST-1 key ceremony:
  the Gate 3 Owner Root (offline), and a K_vol source the kernel can unwrap
  at boot: the Gate 5/6 TPM PolicyAuthorize key with the sealed Slot 0 KEK,
  or the Slot 1 recovery KEK. The in-kernel keyslot unwrap is also not
  written yet. `store_boot_run` refuses TEST-identity keys in a hardware
  staging build before any disk access (host test `stage_test`).
- Proof: `scripts/ck_owner_keys_check.sh` (build only, takes the quiet flag)
  checks the refusals, the generator refusals, and builds the hardware staging
  image from the labelled TEST-fixture files in `tests/fixtures/owner/`
  (public bytes only, distinct from every old TEST constant), then greps the
  ELF and EFI. Ends `CK_OWNER_KEYS_CHECK: PASS`. CI runs it.
- Not covered: the untrusted RFC 8032 TEST 1/2 public key constants
  (`artifact/format.c`, used only by the `CK_SEED0B_TEST_ANCHOR` build and the
  host tools) are still present as data in every image, including hardware
  staging; the ordinary loader trusts no anchor.

## Boot sequence

1. UEFI stub: pre-exit report on ConOut, memory map, `ExitBootServices`.
2. `ck_kernel_entry` (firmware EL, firmware MMU): vectors, PSCI conduit
   from the FADT (HVC or SMC, default SMC), own page tables, stack, heap,
   DMA pool.
3. `ck_enter_el1`: EL2 -> EL1h with the MMU already on our tables.
4. EL1: `mmu: enabled`, `mmu_switch: ...` read back from the registers,
   heap check, guard-page self test, GICv3 from the MADT, 200 ms timer window
   (INTID 30, 10 ms period), `kernel: alive`, `kernel_el: EL1h`.
5. Stages, in order, if linked: `ck_stage_devices`, `ck_stage_security`,
   `ck_stage_store`. Each prints `stage <name>: ok`, `stage <name>: FAIL
   rc=<n>` or `stage <name>: not linked`.
6. `report_kind: final`, then PSCI SYSTEM_RESET (WFI loop if refused).

Every reset (final, panic or fault) first calls the stage hook
`ck_stage_quiesce` once, if linked: the devices stage releases a still-live
NVMe controller (NVMe normal shutdown, CC.SHN = 01b then wait for CSTS.SHST
= 10b, bounded 5 s; if it cannot (fatal status, not ready, timeout) it clears
CC.EN and waits up to 1 s for CSTS.RDY = 0, printing `nvme: shutdown
fallback disable ...`; then bus master off; then the SMMU stream back to abort)
and prints `devices: quiesce before reset nvme=none|released-now|already-released`.
The normal store path already released it, printing `nvme: shutdown normal
cc=..->.. csts=.. shst=complete waited_us=N` before `dma_gate: nvme bus master
revoked`. Code: `dev/nvme_shutdown.c` (register sequence, host-tested in
`svc/tests/stage_test.c`), `dev/devices.c`.

A panic prints `report_kind: panic`; an unexpected exception prints
`report_kind: fault` with ESR, FAR and ELR. Both then reset. Before the drop
to EL1, VBAR_EL2 points at a separate fatal-only table (`ck_vectors_el2`):
any EL2 exception reports ESR_EL2/FAR_EL2/ELR_EL2 (`el=2`) from the emergency
stack and resets; it never returns or touches EL1 state. After the stages,
`mm_usage:` prints the stack high-water mark (painted stack) and the heap
low-water free bytes.

## Memory map the kernel builds

- RAM (UEFI RAM types with the WB attribute): Normal write-back, RW,
  never executable.
- Kernel image: text read-only + executable, rodata and relocations
  read-only, data and BSS read-write. Nothing is writable and executable.
- Kernel stack 256 KiB (stages need >= 128 KiB) with an unmapped guard page below. An exception taken
  with SP below the stack floor switches to a 16 KiB emergency stack so the
  fault report still prints.
- Heap 64 MiB (`ck_alloc`, zeroed, 16-byte aligned) with an unmapped guard
  page on both sides.
- DMA pool 8 MiB, Normal Non-cacheable (`ck_dma_alloc`, never freed).
- MMIO via `ck_mmio_map`: Device-nGnRE, never executable; panics if the
  range overlaps RAM.
- The frame allocator only hands out EfiConventionalMemory, minus the image
  and the handoff, and minus the RSDP, the XSDT/RSDT and every table the root
  lists (whole pages). Tables, stack, heap and pool come from it and are never
  handed out again.

## Notes for stage code

- `ck_puts` prints the string as given; it does not add a newline.
- `\n` is sent as CR LF on the UART.
- IRQs are masked when a stage starts and are masked again after it returns.
  Use `ck_irq_register` + `ck_irq_enable` + `ck_irq_cpu_enable(1)`.
- Stage code is listed in `stage.mk` and linked by `make full`, compiled with
  `STAGE_CFLAGS` first, then the kernel flags and `-U_FORTIFY_SOURCE`. The
  core defines no `ck_stage_*` defaults; the core-only image is checked to
  contain none and the full image to contain all three.
- NVMe DMA is granted only SMMU-confined: the core SMMUv3 service
  (`core/smmu.c`, `core/smmu_svc.c`; ck.h `ck_dma_confine` /
  `ck_dma_unconfine` / `ck_dma_faults`) finds the SMMU through the ACPI IORT
  and maps only the NVMe DMA region for the NVMe stream. With no SMMU, NVMe
  DMA is refused. `CK_QEMU_UNSAFE_DMA=1` (TEST-ONLY, QEMU only, refused with
  `CK_HARDWARE_STAGING`) builds the unconfined bypass used only when no SMMU
  exists, and prints the `WARNING: UNSAFE NVME DMA BYPASS` lines.

## Differences from the Rust kernel

- `guard_page: ok fault=contained` is an addition: the C kernel proves its
  guard pages fault and that the fault is handled. The Rust kernel has no
  such test.
- M3 (threads, EL0, preemption, placement, IPC) runs in the core before the
  stages (`core/m3.c`, `core/sched.c`, `core/ipc.c`, `arch/m3.S`; host tests
  `tests/test_sched.c`, `tests/test_ipc.c`) and prints the same five lines as
  the Rust kernel, plus an extra `ipc_detail:` line. Differences in how:
  the EL0 return uses SPSR 0x3c5 (Rust 0x5); EL0 entry zeroes all general
  registers and TPIDR_EL0/TPIDRRO_EL0; the EL0 window uses ASID 0 with a
  full TLB flush (Rust ASID 1); context switches save x19-x30 and sp only
  (no FP/SIMD; EL0 FP/SIMD traps). Placement is computed from the MADT; no
  secondary core is started (same as Rust). See GATES.md rows 16-20.
- MAIR adds a Normal Non-cacheable attribute (index 2) for the DMA pool.
