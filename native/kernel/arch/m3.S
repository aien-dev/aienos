/* m3.S -- M3 isolation primitives for core/m3.c (port of the global_asm in
 * crates/aienos-kernel/src/thread.rs and user.rs):
 *   ck_ctx_switch       cooperative switch of x19-x30 and sp
 *   ck_thread_start     first frame of a cooperative thread
 *   ck_el0_enter        eret to EL0 with every general register chosen
 *   ck_el0_resume       kernel landing point after an EL0 task exits
 *   ck_el0_demo_*       position-independent EL0 program of the el0 check
 *   ck_ipc_prog_*       position-independent EL0 program of the ipc check
 * The kernel is built -mgeneral-regs-only, so no kernel code keeps live state
 * in FP/SIMD registers and the context holds no d8-d15 (the Rust context
 * does). EL0 FP/SIMD use traps (CPACR_EL1.FPEN = 01 while EL0 runs). */

    .text

/* void ck_ctx_switch(struct ck_ctx *from x0, const struct ck_ctx *to x1)
 * struct ck_ctx { uint64_t x19_x30[12]; uint64_t sp; } */
    .global ck_ctx_switch
    .type ck_ctx_switch, %function
ck_ctx_switch:
    stp x19, x20, [x0, #0]
    stp x21, x22, [x0, #16]
    stp x23, x24, [x0, #32]
    stp x25, x26, [x0, #48]
    stp x27, x28, [x0, #64]
    stp x29, x30, [x0, #80]
    mov x9, sp
    str x9, [x0, #96]
    ldp x19, x20, [x1, #0]
    ldp x21, x22, [x1, #16]
    ldp x23, x24, [x1, #32]
    ldp x25, x26, [x1, #48]
    ldp x27, x28, [x1, #64]
    ldp x29, x30, [x1, #80]
    ldr x9, [x1, #96]
    mov sp, x9
    ret
    .size ck_ctx_switch, . - ck_ctx_switch

/* Entered by the first ck_ctx_switch into a prepared context: x19 = arg,
 * x20 = entry. Never returns: ck_thread_exit parks the thread. */
    .global ck_thread_start
    .type ck_thread_start, %function
ck_thread_start:
    mov x0, x19
    blr x20
    bl ck_thread_exit
1:  b 1b
    .size ck_thread_start, . - ck_thread_start

/* void ck_el0_enter(uint64_t entry x0, uint64_t user_sp x1, const uint64_t regs[31] x2)
 * Saves the kernel callee-saved registers on SP_EL1, records SP_EL1 in
 * ck_el0_kernel_sp, loads x0-x30 from regs (no kernel value reaches EL0) and
 * erets to EL0t with interrupts unmasked. Returns when the EL0 task exits
 * (the syscall handler redirects to ck_el0_resume). */
    .global ck_el0_enter
    .type ck_el0_enter, %function
ck_el0_enter:
    sub sp, sp, #96
    stp x19, x20, [sp, #0]
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x28, [sp, #64]
    stp x29, x30, [sp, #80]
    adrp x9, ck_el0_kernel_sp
    mov x10, sp
    str x10, [x9, :lo12:ck_el0_kernel_sp]
    msr sp_el0, x1
    msr elr_el1, x0
    msr spsr_el1, xzr             /* EL0t, DAIF clear */
    msr tpidrro_el0, xzr          /* vectors.S scratch: never visible to EL0 */
    msr tpidr_el0, xzr
    mov x30, x2
    ldp x0, x1, [x30, #0]
    ldp x2, x3, [x30, #16]
    ldp x4, x5, [x30, #32]
    ldp x6, x7, [x30, #48]
    ldp x8, x9, [x30, #64]
    ldp x10, x11, [x30, #80]
    ldp x12, x13, [x30, #96]
    ldp x14, x15, [x30, #112]
    ldp x16, x17, [x30, #128]
    ldp x18, x19, [x30, #144]
    ldp x20, x21, [x30, #160]
    ldp x22, x23, [x30, #176]
    ldp x24, x25, [x30, #192]
    ldp x26, x27, [x30, #208]
    ldp x28, x29, [x30, #224]
    ldr x30, [x30, #240]
    isb
    eret
    .size ck_el0_enter, . - ck_el0_enter

/* Reached by eret (SPSR = EL1h, DAIF masked) after the EL0 task exits. */
    .global ck_el0_resume
    .type ck_el0_resume, %function
ck_el0_resume:
    adrp x9, ck_el0_kernel_sp
    ldr x9, [x9, :lo12:ck_el0_kernel_sp]
    mov sp, x9
    ldp x19, x20, [sp, #0]
    ldp x21, x22, [sp, #16]
    ldp x23, x24, [sp, #32]
    ldp x25, x26, [sp, #48]
    ldp x27, x28, [sp, #64]
    ldp x29, x30, [sp, #80]
    add sp, sp, #96
    ret
    .size ck_el0_resume, . - ck_el0_resume

/* ---- EL0 programs: copied into a user code page, never run in place ---- */
    .section .rodata.ck_el0, "a"
    .balign 4
/* el0 check (user.rs aienos_user_code): x0 = console handle, x3 = a kernel
 * address. write granted, write with a forged handle, read the kernel
 * address (must fault and be contained), exit 0. */
    .global ck_el0_demo_start, ck_el0_demo_end
ck_el0_demo_start:
    mov x19, x0
    mov x0, x19
    adr x1, 2f
    mov x2, #16
    mov x8, #1
    svc #0
    mov x0, xzr
    adr x1, 2f
    mov x2, #16
    mov x8, #1
    svc #0
    ldr x21, [x3]
    mov x0, xzr
    mov x8, #2
    svc #0
1:  b 1b
    .balign 4
2:  .ascii "el0 user: hello\n"
ck_el0_demo_end:

/* ipc check (user.rs aienos_ipc_code): x20 = handle0, x21 = handle1,
 * x22 = role (1 = A, 2 = B phase 0, bit 8 = B phase 1). Exit code is a
 * bitmask of failed expectations (0 = all as expected). */
    .balign 4
    .global ck_ipc_prog_start, ck_ipc_prog_end
ck_ipc_prog_start:
    mov x23, xzr
    cmp x22, #1
    b.eq 10f
    tbnz x22, #8, 50f
    b 20f
10: mov x0, x20                    /* A: send kind 7 on the channel */
    mov x1, #7
    mov x2, #0x1111
    mov x3, #0x2222
    mov x4, #0x3333
    mov x5, #0xa
    mov x6, #0x1000
    mov x7, #2
    mov x8, #3
    svc #0
    cmp x0, #0
    b.eq 15f
    orr x23, x23, #32
15: mov x0, x21                    /* A: delegate READ on the object to B */
    mov x1, #1
    mov x2, #1
    mov x8, #5
    svc #0
    cmp x0, #0
    b.eq 16f
    orr x23, x23, #64
16: mov x0, x23
    mov x8, #2
    svc #0
70: b 70b
20: mov x0, x20                    /* B0: receive */
    mov x8, #4
    svc #0
    cmp x0, #0
    b.eq 21f
    orr x23, x23, #1
21: cmp x1, #7
    b.eq 22f
    orr x23, x23, #1
22: movz x5, #0x1111
    cmp x2, x5
    b.eq 23f
    orr x23, x23, #1
23: movz x5, #0x2222
    cmp x3, x5
    b.eq 24f
    orr x23, x23, #1
24: mov x0, x21                    /* B0: read object word 0 */
    mov x1, #0
    mov x8, #6
    svc #0
    movz x5, #0xee01
    movk x5, #0xc0ff, lsl #16
    cmp x0, x5
    b.eq 25f
    orr x23, x23, #2
25: mov x0, x21                    /* B0: write must be refused (READ only) */
    mov x1, #0
    mov x2, #0xbad
    mov x8, #7
    svc #0
    cmp x0, #0
    b.ne 26f
    orr x23, x23, #4
26: mov x6, #1                     /* B0: forged handle must be refused */
    lsl x6, x6, #32
    eor x0, x21, x6
    mov x1, #0
    mov x8, #6
    svc #0
    cmp x0, #0
    b.ne 27f
    orr x23, x23, #8
27: mov x0, x23
    mov x8, #2
    svc #0
71: b 71b
50: mov x0, x21                    /* B1: revoked handle must be refused */
    mov x1, #0
    mov x8, #6
    svc #0
    cmp x0, #0
    b.ne 51f
    orr x23, x23, #16
51: mov x0, x23
    mov x8, #2
    svc #0
72: b 72b
ck_ipc_prog_end:

    .bss
    .balign 8
    .global ck_el0_kernel_sp
ck_el0_kernel_sp:
    .space 8
