// P2-5 execution probe: AArch64 EL0, position independent, no relocations.
// Entry (task_runtime ABI): x0 = handle array VA, x1 = handle count,
// x2 = data base VA, x3 = data memory length. All other registers zero.
// Exit code 0 means every check passed; otherwise each set bit names one
// failed check:
//   0x01 handle count != 1        0x02 data word mismatch
//   0x04 data write/readback      0x08 stack write/readback
//   0x10 object read via handle   0x20 forged handle not denied
    .text
    .global _start
_start:
    mov     x19, x0                 // handle array
    mov     x20, x1                 // handle count
    mov     x21, x2                 // data base
    mov     x22, xzr                // failure bitmask

    // 0x01: exactly one granted handle
    cmp     x20, #1
    b.eq    1f
    orr     x22, x22, #0x01
1:
    // 0x02: first data word is "CEXE5-2P" = 0x50322d3545584543
    ldr     x9, [x21]
    movz    x10, #0x4543
    movk    x10, #0x4558, lsl #16
    movk    x10, #0x2d35, lsl #32
    movk    x10, #0x5032, lsl #48
    cmp     x9, x10
    b.eq    2f
    orr     x22, x22, #0x02
2:
    // 0x04: data is writable
    movz    x11, #0xbeef
    movk    x11, #0xdead, lsl #16
    str     x11, [x21, #8]
    ldr     x12, [x21, #8]
    cmp     x11, x12
    b.eq    3f
    orr     x22, x22, #0x04
3:
    // 0x08: stack is writable
    sub     sp, sp, #16
    str     x11, [sp]
    ldr     x12, [sp]
    add     sp, sp, #16
    cmp     x11, x12
    b.eq    4f
    orr     x22, x22, #0x08
4:
    // No handle: both capability checks fail without touching the array.
    cbnz    x20, 5f
    orr     x22, x22, #0x30
    b       7f
5:
    // 0x10: SYS_OBJECT_READ(handle[0], 0) == SEED_OBJECT_WORDS[0]
    ldr     x23, [x19]
    mov     x0, x23
    mov     x1, #0
    mov     x8, #6
    svc     #0
    movz    x10, #0x0001
    movk    x10, #0x5eed, lsl #32
    movk    x10, #0xa1e0, lsl #48
    cmp     x0, x10
    b.eq    6f
    orr     x22, x22, #0x10
6:
    // 0x20: a forged generation must be denied (SYSCALL_DENIED = u64::MAX)
    mov     x9, #1
    lsl     x9, x9, #32
    eor     x0, x23, x9
    mov     x1, #0
    mov     x8, #6
    svc     #0
    cmn     x0, #1
    b.eq    7f
    orr     x22, x22, #0x20
7:
    // SYS_EXIT(bitmask)
    mov     x0, x22
    mov     x8, #2
    svc     #0
8:  b       8b
