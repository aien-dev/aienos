# Evidence: EL0 capability and fault isolation proven in QEMU

Branch: feat/m3-el0-isolation
Base: b9c656f (main after PR #103)
Commit under test: the branch tip including
feat(kernel): add EL0 capability and fault isolation

## Exact successful invocation

    AIENOS_QEMU_VERBOSE=1 AIENOS_QEMU_TIMEOUT=90 bash scripts/qemu_boot_test.sh

Exit 0, QEMU_BOOT: PASS.

## Environment

- Host: spark-b87b
- QEMU 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18)
- Image: aienos-handoff.efi, aarch64-unknown-uefi, --features handoff

## Serial proof (raw lines)

    kernel_el: EL1h
    mmu: enabled
    threads: ok interleave=ABABABABAB
    el0: ok write=granted forged=denied fault=contained exit=0
    kernel: alive

## What the four results demonstrate

1. write=granted: the EL0 task presented the authorized console capability
   handle through SYS_WRITE and the write reached the SPCR console.
2. forged=denied: a forged handle was rejected by the capability table lookup
   and SYS_WRITE returned SYSCALL_DENIED.
3. fault=contained: an EL0 load from a kernel address raised a synchronous data
   abort (ESR EC 0x24); the lower-EL trampoline contained it and resumed the
   task past the faulting instruction without leaving EL1.
4. exit=0: SYS_EXIT returned control cleanly to EL1 at the resume address.

## Layout guard

trap_frame_layout_matches_assembly pins size_of::<TrapFrame>() == 800 and the
x/_pad/elr_el1/spsr_el1/fpcr/fpsr/q offsets (0/248/256/264/272/280/288) that the
trampoline hard-codes. A Rust layout change now fails a test instead of
corrupting exception state.

## Boundary

Emulator only. This says nothing about Machine 1 hardware.
