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
| `core/` | Console, printf, ACPI, reports/panic/PSCI reset, `kmain.c`. |
| `tests/` | Host unit tests. |
| `../boot/` | Minimal UEFI entry stub (one image with the kernel). |

## Build and test

    make -C native/kernel            # target/native-kernel/BOOTAA64.EFI
    make -C native/kernel test       # host tests, ends CK_CORE_HOST: PASS
    make -C native/kernel sanitize   # same under ASan + UBSan
    scripts/qemu_ck_boot_test.sh     # QEMU boot, ends AIENOS_CK_M1: PASS

Toolchain: gcc, binutils (ld, objcopy, nm, readelf), make, shell. On a
non-aarch64 host the Makefile uses the `aarch64-linux-gnu-` prefix.
Output lands in `<repo>/target/native-kernel` (ignored by git).

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
- Link stage code with `STAGE_SRCS=...` (compiled here with the kernel flags,
  `STAGE_CFLAGS` and include paths for native/disk, store, m5, crypto,
  capability, argus and net) or `STAGE_OBJS=...` (prebuilt objects; build
  them with `make print-kcflags`).

## Differences from the Rust kernel

- `guard_page: ok fault=contained` is an addition: the C kernel proves its
  guard pages fault and that the fault is handled. The Rust kernel has no
  such test.
- M3 features (threads, EL0, preemption, placement, IPC) are not implemented
  yet; the QEMU script reports them as NOT_RUN.
- MAIR adds a Normal Non-cacheable attribute (index 2) for the DMA pool.
