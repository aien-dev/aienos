# Evidence: timer-driven preemption and deterministic MADT placement in QEMU

Branch: feat/m3-topology-scheduler
Base: 0b0dc82 (main after PR #104)
Commit under test: the branch tip including
feat(scheduler): timer-driven preemption with MADT-aware placement

## Exact successful invocation

    AIENOS_QEMU_VERBOSE=1 AIENOS_QEMU_TIMEOUT=90 bash scripts/qemu_boot_test.sh

Exit 0, QEMU_BOOT: PASS.

## Environment

- Host: spark-b87b
- QEMU 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18), virt machine, gic-version=3, -smp 4
- Image: aienos-handoff.efi, aarch64-unknown-uefi, --features handoff

## Serial proof (raw lines)

    kernel_el: EL1h
    mmu: enabled
    threads: ok interleave=ABABABABAB
    el0: ok write=granted forged=denied fault=contained exit=0
    preempt: ok a=5716769 b=3798659 switches=4
    placement: worker0=class0/core0 worker1=class0/core1
    kernel: alive

## What the results demonstrate

- preempt: the timer IRQ (GIC INTID 30) preempts the EL1 boot context and
  round-robins two runnable workers through the 800-byte TrapFrame dispatcher;
  both counters advanced (a, b > 0) across 4 switches before the demo quiesced.
- placement: the two workers were placed deterministically from the MADT
  efficiency classes. QEMU exposes 4 homogeneous cores (class 0), so
  place_task() yields class0/core0 then class0/core1. The heterogeneous path
  (class 0 and class 1 cores) is covered by the host test
  placement_fills_lowest_class_first_then_wraps.
- context state: the preemption frame is the same full 800-byte TrapFrame
  (x0-x30, ELR/SPSR, FPCR/FPSR, q0-q31) guarded by
  trap_frame_layout_matches_800_bytes_and_16_byte_alignment, so SIMD/FP state
  survives switches.

## IRQ model

The EL1 IRQ trampoline now saves the complete TrapFrame and calls
thread::aienos_irq_dispatcher, which acknowledges the interrupt, re-arms the
timer, ends the interrupt in the GIC, and returns the next frame to restore.
handoff's timer_irq is a pure counter. Vector slot 8 (EL0 containment, PR #104)
and slot 5 (IRQ) routing are unchanged.

## Boundary

Emulator only. QEMU exposes one efficiency class, so cross-class migration is
host-tested, not observed on hardware. No SMP bring-up of secondary cores is
exercised; placement is the deterministic policy the scheduler will apply when
secondary cores are started.
