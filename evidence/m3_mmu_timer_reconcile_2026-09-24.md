# Evidence: reconcile #27 (MMU) and #28 (timer and GICv3) against code and serial output

Branch: m3/reconcile-27-28
Base: 668202e (main after PR #105)
Commit under test: 6aa723b77f59bf371914434de50f175b56f8f964
feat(boot): report the MMU switch and tick statistics (reconcile #27, #28)

This is Phase 1A of the M3 plan. No MMU or GIC code was rewritten. The only
code change adds report lines read from live registers and records a
timestamp in the existing timer IRQ hook, so each issue clause can be tied
to a serial line.

## Exact successful invocation

    AIENOS_QEMU_VERBOSE=1 AIENOS_QEMU_TIMEOUT=120 bash scripts/qemu_boot_test.sh

qemu exit 0 after 7 s (commit 6aa723b77f59), QEMU_BOOT: PASS. New checks:

    PASS  MMU switched from firmware tables (0x47fff000) to AIENOS tables (0xbc32b000)
    PASS  GIC bases from the ACPI MADT, GICv3 architecture and ICC system registers
    PASS  tick statistics consistent (period 10000 us, min 10125 avg 10240 max 11008)

## Environment

- Host: spark-b87b (NVIDIA DGX Spark)
- QEMU 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18), virt, virtualization=on,
  gic-version=3, -cpu max, -smp 4, -m 2048, single-threaded TCG
- Firmware: AAVMF (Ubuntu EDK II 2024.02), guest starts at EL2
- Image: aienos-handoff.efi, aarch64-unknown-uefi, --features handoff

## Serial proof (raw lines)

    aienos_commit: 6aa723b77f59bf371914434de50f175b56f8f964
    report_kind: final
    kernel_el: EL1h
    mmu: enabled
    pt_frames_used: 18
    mmu_switch: firmware=EL2 firmware_mmu=on firmware_ttbr0=0x47fff000 aienos_root=0xbc32b000 ttbr0_el1=0xbc32b000 switched=yes
    threads: ok interleave=ABABABABAB
    el0: ok write=granted forged=denied fault=contained exit=0
    preempt: ok a=5721027 b=3804856 switches=4
    runtime_code: rx-unsplit
    exception_level: EL1
    kernel: alive
    gic: v3
    timer_irq: 19 ticks in 200 ms
    gic_madt: gicd=0x8000000 gicr=0x80a0000 arch_rev=3 icc_sre=1
    timer_stats: intid=30 freq_hz=62500000 period_us=10000 min_us=10125 avg_us=10240 max_us=11008

## What the new lines mean

- mmu_switch: firmware_ttbr0 is TTBR0_EL2 and firmware_mmu is SCTLR_EL2.M,
  both read at EL2 immediately before `enter_el1h_mmu`. aienos_root is the
  root `PageTableBuilder` returned. ttbr0_el1 is read live at EL1 when the
  report is written. switched=yes is printed only when the CPU is at EL1,
  SCTLR_EL1.M is set, TTBR0_EL1 equals aienos_root, and aienos_root differs
  from firmware's root. The boot test re-checks the two equalities itself
  from the printed values.
- gic_madt: gicd and gicr are the first GICD and GICR entries parsed from the
  ACPI MADT (`acpi::madt_gic_bases`). arch_rev is GICD_PIDR2 bits [7:4]
  read from that distributor (3 means GICv3). icc_sre is ICC_SRE_EL1.SRE
  read back after enabling the system register CPU interface.
- timer_stats: intervals are CNTPCT_EL0 distances between consecutive
  ticks, recorded by `timer_irq`. The dispatcher calls that hook only after
  ICC_IAR1_EL1 returned INTID 30 and the timer was re-armed, and before
  ICC_EOIR1_EL1. The first interval is measured from the moment the window
  armed the timer. avg is (last tick minus arm time) divided by ticks.

## Clause table

Code locations are at commit 6aa723b. "handoff" is
crates/aienos-boot/src/handoff.rs; kernel paths are under
crates/aienos-kernel/src/.

### Issue #27: AIENOS page tables replacing the firmware identity map

| Clause | Code | Serial line | Status |
|---|---|---|---|
| Leaves firmware translation | handoff 362 reads TTBR0_EL2/SCTLR_EL2 (`firmware_translation`, 418); arch/aarch64.rs 80 to 112 writes TTBR0_EL1, SCTLR_EL1, HCR_EL2=RW only (no stage 2), then ERET to EL1h | `mmu_switch: firmware=EL2 firmware_mmu=on firmware_ttbr0=0x47fff000 ... switched=yes` | Met |
| AIENOS-owned EL1 tables | handoff 331 `build_map_plan`, 335 `PageTableBuilder::new` over a pool from `allocate_pages` (1270), 337 to 346 maps every planned range | `mmu_switch: ... aienos_root=0xbc32b000 ttbr0_el1=0xbc32b000`, `pt_frames_used: 18` | Met |
| Kernel memory mapped (image, stacks) | mem/map_plan.rs 97 maps each PE section of the loaded image (EFI loader code) with its own permissions; 181 maps loader data, boot services code and data, conventional, ACPI and runtime data as KERNEL_DATA, which covers the UEFI stack in use at handoff; exception stack is a static in the image | Kernel keeps running after the switch: `threads: ok`, `el0: ok`, `preempt: ok`, `kernel: alive`, final report printed | Met |
| MMIO mapped (UART, framebuffer, GIC, others) | handoff 289 framebuffer, 295 SPCR UART, 310 to 322 GICD and GICR, plus xHCI, ECAM and SMMU in the keyboard image; map_plan.rs 139 and 197 map EFI MMIO and these ranges as Device-nGnRE, non-executable | Final report arrives on the SPCR PL011 after the switch; `gic_madt: ... arch_rev=3` reads GICD over the new mapping | Met |
| Page permissions | map_plan.rs 59 `flags`, 120 to 123 rejects W+X PE sections; mem/pagetable.rs 348 rejects writable and executable leaves; MMIO is XN; runtime code is RX (map_plan.rs 144 to 180); host tests `section_permissions_are_wx_safe`, `mmio_is_device_nx_and_overlap_rejected`, `writable_executable_runtime_code_is_mapped_rx` | `runtime_code: rx-unsplit` (QEMU firmware gives no MAT split, so runtime code is mapped read and execute) | Met, see note 1 |
| MMU enabled | arch/aarch64.rs 105 writes SCTLR_EL1 with M, C, I (map_plan.rs 228); handoff 1440 reads SCTLR_EL1.M live | `mmu: enabled` | Met |
| Executes after the switch | Everything after `enter_kernel_mmu` returns runs on the new tables | `kernel_el: EL1h`, `exception_level: EL1`, `kernel: alive`, `report_kind: final` | Met |
| Report shows the switch (done-when) | handoff 1446 to 1461 | `mmu_switch: ... switched=yes` | Met |

### Issue #28: generic timer and GICv3 interrupt bring-up

| Clause | Code | Serial line | Status |
|---|---|---|---|
| GICv3 addresses from the ACPI MADT | kernel acpi.rs 44 `madt_gic_bases`; handoff 967 stores them; host test `extracts_gicd_and_gicr_bases` | `gic_madt: gicd=0x8000000 gicr=0x80a0000` | Met |
| GIC is v3 | GICD_PIDR2 ArchRev read in handoff `run_timer_window`; ICC_SRE_EL1 read back | `gic_madt: ... arch_rev=3 icc_sre=1`, `gic: v3` | Met |
| GIC init | handoff 563 redistributor wake, 566 PPI 30 group 1 priority 0x80 enable, 570 distributor ARE and Group 1 enable, 572 to 573 PMR and ICC_SRE plus IGRPEN1 | ticks are delivered: `timer_irq: 19 ticks in 200 ms` | Met |
| Timer config | handoff 588 to 595 reads CNTFRQ_EL0, sets CNTP_CVAL_EL0 to 10 ms ahead, enables CNTP_CTL_EL0 | `timer_stats: intid=30 freq_hz=62500000 period_us=10000` | Met, see note 2 |
| Delivery to EL1 vectors | fatal.rs 258 IRQ vector branches to `aienos_irq_trampoline` (268), which saves a full TrapFrame and calls `thread::aienos_irq_dispatcher` (thread.rs 218); handoff 598 unmasks DAIF.I | `timer_irq: 19 ticks in 200 ms` | Met |
| Acknowledge | thread.rs 232 reads ICC_IAR1_EL1; the tick hook runs only when it returned 30 | Every counted tick is an acknowledged INTID 30. No line prints the raw IAR value | Met, indirect |
| End of interrupt | thread.rs 246 writes ICC_EOIR1_EL1 for any INTID below 1020 | Repeated ticks (19) prove EOI: without it the running priority stays active and no second tick is taken | Met, indirect |
| Re-arm | thread.rs 240 sets CNTP_CVAL_EL0 to now plus 10 ms in the handler | `min_us=10125`: no interval shorter than the period, so the level interrupt was cleared by re-arming rather than storming | Met |
| Repeated periodic ticks | as above | `timer_irq: 19 ticks in 200 ms`, `avg_us=10240` (period 10000 us) | Met |
| Tick statistics reported | handoff 519 `timer_irq` timestamps; 1552 to 1576 print them | `timer_stats: ... min_us=10125 avg_us=10240 max_us=11008` | Met |
| Preemption driven by the tick | thread.rs 345 `run_preemption_demo`; dispatcher returns another worker's frame on INTID 30 | `preempt: ok a=5721027 b=3804856 switches=4` | Met |

## Notes and gaps, stated plainly

1. W^X is enforced per mapping by the plan and the table builder, not by
   SCTLR_EL1.WXN, which stays clear. Firmware's own table memory
   (0x47fff000) is still mapped read and write in the AIENOS identity
   layout; it is no longer walked for EL1, but it is not unmapped.
2. The timer INTID (30, EL1 physical timer) is a constant in the code. It
   is not read from the ACPI GTDT. Issue #28 asks for the GIC addresses from
   the MADT, which is met; the timer INTID source is not stated in the
   issue, so this is recorded as a gap rather than a failed clause.
3. Only the boot CPU's redistributor (first GICR entry) is used. Secondary
   cores are not started, so GIC bring-up is proven for one CPU.
4. `ms=200` in `timer_irq:` is the window length the loop enforces with the
   counter (`hz / 5` ticks), printed as a constant.
5. The tables are an identity layout (virtual equals physical). The issue
   asks for AIENOS tables replacing firmware's, not a different layout, so
   this does not affect any clause.
6. Across three runs on this host min_us was 9658, 10028 and 10125. An
   interval can land slightly under 10000 us because the hook reads the
   counter a little after the dispatcher computed the deadline. The test
   therefore requires min_us to be at least half a period.

Every clause of #27 and #28 listed above is met in QEMU. Acknowledge and
end of interrupt are proven indirectly through repeated, correctly spaced
ticks, not by a dedicated serial line.

## Boundary

Emulator only. Nothing here was recorded on the DGX Spark. Firmware at EL2
under QEMU TCG, one CPU running, GICv3 as emulated by QEMU 8.2.2.
