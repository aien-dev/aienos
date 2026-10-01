/* smp_entry.S -- PSCI CPU_ON entry point for secondary cores (core/smp.c).
 *
 * Entered with the MMU and caches off, x0 = context_id = the core's
 * struct ck_smp_cpu (identity mapped, cleaned to PoC by the boot core), at
 * the EL PSCI chose: EL2 when EL2 exists (QEMU 8.2.2 target/arm/tcg/psci.c:144),
 * else EL1. Only aligned 8-byte loads from the context happen before the MMU
 * is on. EL2: fatal-only EL2 vectors, then the boot core's own EL2 -> EL1h
 * path ck_enter_el1 (ADR 0009: HCR_EL2.RW, VMPIDR_EL2 = this core's MPIDR,
 * timer and GIC system register access, MMU on with the boot core's tables).
 * EL1: ck_switch_el1. Both land in ck_smp_secondary_main(ctx) on the core's
 * own stack. Any other EL parks here. Context offsets: core/smp.c. */
    .text
    .global ck_smp_entry
    .type ck_smp_entry, %function
    .balign 8
ck_smp_entry:
    msr daifset, #0xf
    mov x19, x0
    mrs x9, CurrentEL
    ubfx x9, x9, #2, #2
    ldp x0, x1, [x19, #0]          /* root, mair */
    ldp x2, x3, [x19, #16]         /* tcr, sctlr */
    ldr x4, [x19, #32]             /* stack top */
    adrp x5, ck_smp_secondary_main
    add x5, x5, :lo12:ck_smp_secondary_main
    mov x6, x19
    cmp x9, #2
    b.ne 1f
    adrp x10, ck_vectors_el2
    add x10, x10, :lo12:ck_vectors_el2
    msr vbar_el2, x10
    isb
    b ck_enter_el1
1:  cmp x9, #1
    b.eq ck_switch_el1
2:  wfe
    b 2b
    .size ck_smp_entry, . - ck_smp_entry
