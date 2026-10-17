/* trap.S -- x86_64 descriptor-table loads, the 256 interrupt stubs and the
 * stack switch for AIENOS-IMAC-KERNEL-0 (native/kernel/x86). The C side is
 * compiled -mabi=ms: arguments in rcx, rdx, r8, r9, 32 bytes of shadow space
 * reserved by the caller, rax/rcx/rdx/r8-r11 caller-saved. */

    .text

/* void ck_x86_load_gdt(const void *gdtr, u16 code_sel, u16 data_sel, u16 tss_sel)
 * Loads the GDT, reloads CS with a far return and the data segments, then
 * the task register. */
    .globl ck_x86_load_gdt
ck_x86_load_gdt:
    lgdt (%rcx)
    mov %r8w, %ds
    mov %r8w, %es
    mov %r8w, %ss
    mov %r8w, %fs
    mov %r8w, %gs
    movzwq %dx, %rdx
    lea 1f(%rip), %rax
    push %rdx
    push %rax
    lretq
1:  test %r9w, %r9w                    /* tss_sel 0: no task register (secondary cores) */
    jz 2f
    ltr %r9w
2:  ret

/* noreturn void ck_x86_call_on_stack(void (*fn)(void *), void *arg, u64 sp)
 * sp is 16-byte aligned; the call leaves the callee at sp - 40 = 8 mod 16,
 * as a normal call would. */
    .globl ck_x86_call_on_stack
ck_x86_call_on_stack:
    mov %r8, %rsp
    sub $32, %rsp
    mov %rcx, %rax
    mov %rdx, %rcx
    call *%rax
    ud2

/* 256 stubs, each at ck_x86_isr_stubs + 16 * vector. Vectors that push an
 * error code (8, 10-14, 17, 21, 29, 30) skip the dummy push. */
    .section .text.isr, "ax"
    .globl ck_x86_isr_stubs
    .balign 16
ck_x86_isr_stubs:
    .set vec, 0
    .rept 256
    .org ck_x86_isr_stubs + vec * 16
    .if (vec == 8) || ((vec >= 10) && (vec <= 14)) || (vec == 17) || (vec == 21) || (vec == 29) || (vec == 30)
    .else
    pushq $0
    .endif
    pushq $vec
    jmp isr_common
    .set vec, vec + 1
    .endr
    .org ck_x86_isr_stubs + 256 * 16

isr_common:
    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rsi
    push %rdi
    push %rbp
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15
    cld
    mov %rsp, %rcx          /* struct ck_x86_frame * */
    mov %rsp, %rbx          /* callee-saved under both ABIs */
    and $-16, %rsp
    sub $32, %rsp
    call ck_x86_trap
    mov %rbx, %rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rbp
    pop %rdi
    pop %rsi
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax
    add $16, %rsp           /* vector, error code */
    iretq

    .section .note.GNU-stack, "", @progbits
