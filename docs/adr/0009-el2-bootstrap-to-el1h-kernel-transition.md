# ADR 0009: Two-Stage Exception Level Architecture (EL2 Bootstrap to EL1h Kernel)

Status: Accepted by operator.

## Context

Both the physical DGX Spark (Grace CPU) firmware and QEMU AArch64 UEFI emulation (AAVMF / EDK II) enter UEFI applications at Exception Level 2 (EL2).

The early handoff image (`aienos-handoff`) currently transfers execution to `aienos-kernel` directly at EL2. While this allowed the first native boot proof (M2_GATE PASS) to succeed without intermediate transition complexity, it creates severe architectural conflicts for Milestone 3 (Kernel Isolation):

1. **Translation Register Collision**: Standard 64-bit ARM (AArch64) supervisor operating systems execute at EL1. The translation control registers (`TCR_EL1`), page table base pointers (`TTBR0_EL1`, `TTBR1_EL1`), memory attribute registers (`MAIR_EL1`), and system control register (`SCTLR_EL1`) are defined for EL1. Running the kernel at EL2 while programming EL1 registers introduces undefined behavior and bypasses MMU enforcement.
2. **Conflation of Hypervisor and Operating System Roles**: Operating at EL2 conflates virtualization machinery with core kernel execution. AIENOS is an agent-native operating system, not a hypervisor.
3. **User Task Privilege Separation**: When future EL0 tasks (agent runtimes, model workers, sandboxed drivers) are scheduled, returning to EL0 from EL2 requires different exception return semantics (`SPSR_EL2` vs `SPSR_EL1`) and complicates address space isolation.

Before implementing MMU page tables (`mmu.rs`), task switching (`task.rs`), exception routing, or scheduler primitives, the exception level hierarchy must be formally established.

## Decision

Establish a strict two-stage exception level entry hierarchy:

```text
UEFI Firmware (EL2)
  |
  v
Early AIENOS Boot Handoff (EL2)
  |
  v
Minimal EL2 Bootstrap Stub
  +-- Validate current exception level (CurrentEL == EL2)
  +-- Enforce known EL2 register state (HCR_EL2, CPTR_EL2)
  +-- Grant EL1 direct access to Generic Physical/Virtual Timers (CNTHCTL_EL2, CNTVOFF_EL2)
  +-- Enable EL1 floating-point and NEON/SIMD access without trapping (CPACR_EL1)
  +-- Install minimal EL2 emergency vectors (VBAR_EL2) to capture early bootstrap faults
  +-- Set target kernel entrypoint in ELR_EL2
  +-- Set target execution mode in SPSR_EL2 = 0x3c5 (EL1h, dedicated SP_EL1, DAIF masked)
  |
  v (eret)
AIENOS Kernel Core (EL1h)
  +-- Initialize SP_EL1 to dedicated kernel stack
  +-- Install production exception vector table (VBAR_EL1)
  +-- Configure EL1 MMU translation tables (TCR_EL1, TTBR0_EL1, TTBR1_EL1, MAIR_EL1)
  +-- Initialize GICv3 CPU interface and architectural timers
  +-- Initialize cooperative task scheduler and AEGIS boundaries
  |
  v (future eret to EL0)
Sandboxed User Tasks (EL0)
```

### Precondition for Milestone 3 Implementation

No MMU implementation (`mmu.rs`) or task switcher (`task.rs`) may be merged into `main` before the EL2 to EL1h transition stub is implemented and verified under QEMU emulation.

The QEMU boot test (`scripts/qemu_boot_test.sh`) must verify:
1. Entry into early handoff at EL2.
2. Successful execution of `eret` to EL1h.
3. Kernel reporting `exception_level: EL1` upon reaching `kernel: alive`.

## Invariants

1. **Kernel Execution Level**: The main AIENOS kernel (`aienos-kernel`) executes strictly at EL1h.
2. **Bootstrap Containment**: EL2 execution is restricted to the minimal bootstrap handoff stub. No general kernel logic, memory allocation, or runtime scheduling may execute at EL2.
3. **Translation Scope**: `mmu.rs` targets AArch64 stage-1 translation registers (`TCR_EL1`, `TTBR0_EL1`, `TTBR1_EL1`, `MAIR_EL1`) exclusively.
4. **Secrets Invariant**: NO PLAINTEXT SECRETS IN REPOSITORY OR BUILD ARTIFACTS.
5. **Unslop Standard**: Zero em dashes, zero en dashes, and direct technical documentation.

## Consequences

- The `aienos-boot` crate or kernel assembly entrypoint will introduce an explicit `el2_to_el1_transition` routine.
- The `aienos-kernel` boot report will reflect `exception_level: EL1`.
- The physical DGX Spark and QEMU test suites will demonstrate deterministic `eret` transition before page table enablement.
- The architectural foundation for M3 issues #26 through #30 is unblocked and correctly ordered.
