/* vectors.S -- exception vectors, EL2 -> EL1h entry, recoverable probe.
 * ck_vectors serves VBAR_EL1 only; ck_vectors_el2 (fatal-only) serves VBAR_EL2
 * before the drop to EL1.
 * TPIDR_EL1 and TPIDRRO_EL0 are scratch registers in the entry path (no EL0
 * runs in this core yet). Frame layout: struct ck_frame in arch.h. */
#define FRAME 272

    .text

.macro VENTRY idx
    .balign 0x80
    msr tpidr_el1, x0
    msr tpidrro_el0, x1
    mov x1, #\idx
    b ck_vec_common
.endm

    .balign 2048
    .global ck_vectors
ck_vectors:
    VENTRY 0
    VENTRY 1
    VENTRY 2
    VENTRY 3
    VENTRY 4
    VENTRY 5
    VENTRY 6
    VENTRY 7
    VENTRY 8
    VENTRY 9
    VENTRY 10
    VENTRY 11
    VENTRY 12
    VENTRY 13
    VENTRY 14
    VENTRY 15

ck_vec_common:
    /* Stack guard: if SP is within one frame of the floor (overflow into the
     * guard page), continue on the emergency stack so the fault can be
     * reported instead of recursing. */
    adrp x0, ck_stack_floor
    ldr x0, [x0, :lo12:ck_stack_floor]
    add x0, x0, #FRAME
    cmp sp, x0
    b.hs 1f
    adrp x0, ck_emergency_stack_top
    add x0, x0, :lo12:ck_emergency_stack_top
    mov sp, x0
1:  sub sp, sp, #FRAME
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    mrs x2, tpidr_el1
    mrs x3, tpidrro_el0
    stp x2, x3, [sp, #0]
    mrs x2, elr_el1
    stp x30, x2, [sp, #240]
    mrs x2, spsr_el1
    stp x2, x1, [sp, #256]
    mov x0, sp
    cmp x1, #5
    b.ne 2f
    bl ck_irq_dispatch
    b 3f
2:  bl ck_exception
3:  ldp x30, x2, [sp, #240]
    msr elr_el1, x2
    ldr x2, [sp, #256]
    msr spsr_el1, x2
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    add sp, sp, #FRAME
    eret

/* EL2 vectors, live only between the kernel entry at EL2 and the drop to EL1.
 * Every EL2 exception is fatal: mask everything, move to the emergency stack
 * (the firmware stack may be the cause) and report ESR_EL2/FAR_EL2/ELR_EL2,
 * then reset. Nothing here touches the EL1 state or returns. */
.macro VENTRY_EL2 idx
    .balign 0x80
    msr daifset, #0xf
    mov x0, #\idx
    b ck_vec_el2_common
.endm

    .balign 2048
    .global ck_vectors_el2
ck_vectors_el2:
    VENTRY_EL2 0
    VENTRY_EL2 1
    VENTRY_EL2 2
    VENTRY_EL2 3
    VENTRY_EL2 4
    VENTRY_EL2 5
    VENTRY_EL2 6
    VENTRY_EL2 7
    VENTRY_EL2 8
    VENTRY_EL2 9
    VENTRY_EL2 10
    VENTRY_EL2 11
    VENTRY_EL2 12
    VENTRY_EL2 13
    VENTRY_EL2 14
    VENTRY_EL2 15

ck_vec_el2_common:
    adrp x1, ck_emergency_stack_top
    add x1, x1, :lo12:ck_emergency_stack_top
    mov sp, x1
    mov x29, xzr
    mov x30, xzr
    bl ck_el2_fatal
1:  wfi
    b 1b

/* int ck_probe_read(const volatile void *addr) */
    .global ck_probe_read
    .type ck_probe_read, %function
ck_probe_read:
    adrp x1, ck_probe_state
    add x1, x1, :lo12:ck_probe_state
    adr x2, 0f
    str x2, [x1, #8]
    adr x2, 1f
    str x2, [x1, #0]
    dsb sy
    isb
0:  ldr x3, [x0]
    str xzr, [x1, #0]
    mov x0, #0
    ret
1:  mov x0, #1
    ret
    .size ck_probe_read, . - ck_probe_read

/* ck_enter_el1(root x0, mair x1, tcr x2, sctlr x3, sp x4, entry x5, arg x6)
 * ADR 0009: known EL2 state, EL1 timer and FP access, GIC system registers
 * for EL1, then eret to EL1h (SPSR 0x3c5: EL1h, DAIF masked) with the EL1
 * MMU already on our tables. */
    .global ck_enter_el1
    .type ck_enter_el1, %function
ck_enter_el1:
    msr daifset, #0xf
    mrs x9, midr_el1
    msr vpidr_el2, x9
    mrs x9, mpidr_el1
    msr vmpidr_el2, x9
    mov x9, #(1 << 31)             /* HCR_EL2.RW: EL1 is AArch64; no traps, no stage 2 */
    msr hcr_el2, x9
    mov x9, #0x33ff                /* CPTR_EL2: RES1 bits, no FP/SIMD traps */
    msr cptr_el2, x9
    msr hstr_el2, xzr
    msr vttbr_el2, xzr
    mov x9, #3                     /* CNTHCTL_EL2: EL1PCTEN | EL1PCEN */
    msr cnthctl_el2, x9
    msr cntvoff_el2, xzr
    mrs x9, id_aa64pfr0_el1        /* GIC system registers implemented? */
    ubfx x9, x9, #24, #4
    cbz x9, 1f
    mrs x9, S3_4_C12_C9_5          /* ICC_SRE_EL2 */
    mov x10, #0x9                  /* SRE | Enable (EL1 may use ICC_SRE_EL1) */
    orr x9, x9, x10
    msr S3_4_C12_C9_5, x9
    isb
    msr S3_4_C12_C11_0, xzr        /* ICH_HCR_EL2: no virtual CPU interface */
1:  mov x9, #(3 << 20)             /* CPACR_EL1.FPEN: no FP/SIMD traps */
    msr cpacr_el1, x9
    msr mair_el1, x1
    msr tcr_el1, x2
    msr ttbr0_el1, x0
    msr ttbr1_el1, xzr
    dsb ish
    tlbi vmalle1
    dsb ish
    ic iallu
    dsb ish
    isb
    msr sctlr_el1, x3
    isb
    msr sp_el1, x4
    adrp x9, ck_vectors
    add x9, x9, :lo12:ck_vectors
    msr vbar_el1, x9
    mov x9, #0x3c5
    msr spsr_el2, x9
    msr elr_el2, x5
    mov x0, x6
    mov x30, xzr
    mov x29, xzr
    isb
    eret
    .size ck_enter_el1, . - ck_enter_el1

/* ck_switch_el1: firmware handed over at EL1 already. Turn the MMU off,
 * install our tables, turn it on, switch stacks. Code runs identity mapped
 * in both regimes, so the PC stays valid. */
    .global ck_switch_el1
    .type ck_switch_el1, %function
ck_switch_el1:
    msr daifset, #0xf
    mrs x9, sctlr_el1
    bic x9, x9, #1
    msr sctlr_el1, x9
    isb
    msr mair_el1, x1
    msr tcr_el1, x2
    msr ttbr0_el1, x0
    msr ttbr1_el1, xzr
    dsb ish
    tlbi vmalle1
    dsb ish
    ic iallu
    dsb ish
    isb
    msr sctlr_el1, x3
    isb
    mov sp, x4
    adrp x9, ck_vectors
    add x9, x9, :lo12:ck_vectors
    msr vbar_el1, x9
    isb
    mov x0, x6
    mov x29, xzr
    mov x30, xzr
    br x5
    .size ck_switch_el1, . - ck_switch_el1

    .bss
    .balign 16
ck_emergency_stack:
    .space 16384
ck_emergency_stack_top:
