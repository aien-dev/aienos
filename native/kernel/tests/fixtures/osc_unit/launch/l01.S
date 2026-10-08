// l01.S: hand-assembled TEST functions for the C3-3a task-launch gate.
// Every word is in the OSC-emitted subset (spec 8.4); admission re-checks it.
// x7 = OscRt *, x30 = the runtime return stub, args in x0..x5.
    .text
    .global _start
_start:
// fn 0  trap(code: u64) -> u64 : the real trap sequence (osc_cg.c trap_seq), code in x0
trap:
    mov x1, x0
    mov x0, x7
    ldr x16, [x0, #16]
    blr x16
    brk #1
// fn 1  spin() -> u64 : never finishes (budget test)
spin:
    b spin
// fn 2  peek0() -> u64 : read address 0 (unmapped): a CPU fault
peek0:
    movz x0, #0
    ldr x0, [x0]
    ret
// fn 3  poke_rt() -> u64 : write the OscRt table (read-only to the unit): a CPU fault
poke_rt:
    str x0, [x7]
    ret
// fn 4  bare_brk() -> u64 : reaches a brk guard directly (spec 8.4: a fault, never TRAPPED)
bare_brk:
    brk #3
// fn 5  exec_stack() -> u64 : write a `ret` into the stack and call it. W^X: must fault.
exec_stack:
    sub sp, sp, #16
    movz x1, #0x03c0
    movk x1, #0xd65f, lsl #16
    str x1, [sp]
    add x0, sp, #0
    blr x0
    movz x0, #42
    add sp, sp, #16
    ret
// fn 6  overflow() -> u64 : grow the stack until it leaves the mapped stack
overflow:
    sub sp, sp, #16
    str x0, [sp]
    b overflow
// fn 7  counter(ws: cells, n: u64) -> u64 : ws[0] += 1, return it (workspace persistence)
counter:
    ldr x2, [x0]
    add x2, x2, #1
    str x2, [x0]
    orr x0, xzr, x2
    ret
// fn 8  peek_kernel(addr: u64) -> u64 : read a kernel virtual address (mapped EL1-only): a CPU fault
peek_kernel:
    ldr x0, [x0]
    ret
// fn 9  jump_ws(ws: cells, n: u64) -> u64 : call the code at x0 (the caller pre-loads a valid `ret` there); returns 42
//        if that works, so only an execute-never workspace page makes this fault
jump_ws:
    sub sp, sp, #16
    str x30, [sp]
    blr x0
    ldr x30, [sp]
    add sp, sp, #16
    movz x0, #42
    ret
// fn 10 jump_in(in: bytes, n: u64) -> u64 : same, into the input window (caller supplies the `ret` bytes)
jump_in:
    sub sp, sp, #16
    str x30, [sp]
    blr x0
    ldr x30, [sp]
    add sp, sp, #16
    movz x0, #42
    ret
// fn 11 dirty() -> u64 : leave a nonzero value in x1..x29 (for the register-clearing check)
dirty:
    movz x1, #0x1111
    movz x2, #0x2222
    movz x3, #0x3333
    movz x4, #0x4444
    movz x5, #0x5555
    movz x6, #0x6666
    movz x8, #0x8888
    movz x9, #0x9999
    movz x10, #0xaaaa
    movz x11, #0xbbbb
    movz x12, #0xcccc
    movz x13, #0xdddd
    movz x14, #0xeeee
    movz x15, #0xffff
    movz x16, #0x1616
    movz x17, #0x1717
    movz x18, #0x1818
    movz x19, #0x1919
    movz x20, #0x2020
    movz x21, #0x2121
    movz x22, #0x2222
    movz x23, #0x2323
    movz x24, #0x2424
    movz x25, #0x2525
    movz x26, #0x2626
    movz x27, #0x2727
    movz x28, #0x2828
    movz x29, #0x2929
    movz x0, #1
    ret
// fn 12 regs_or() -> u64 : OR of x0..x29 as seen at entry, except x7 (the OscRt pointer, set by contract).
// Zero means every other register was cleared by the launcher.
regs_or:
    orr x0, x0, x1
    orr x0, x0, x2
    orr x0, x0, x3
    orr x0, x0, x4
    orr x0, x0, x5
    orr x0, x0, x6
    orr x0, x0, x8
    orr x0, x0, x9
    orr x0, x0, x10
    orr x0, x0, x11
    orr x0, x0, x12
    orr x0, x0, x13
    orr x0, x0, x14
    orr x0, x0, x15
    orr x0, x0, x16
    orr x0, x0, x17
    orr x0, x0, x18
    orr x0, x0, x19
    orr x0, x0, x20
    orr x0, x0, x21
    orr x0, x0, x22
    orr x0, x0, x23
    orr x0, x0, x24
    orr x0, x0, x25
    orr x0, x0, x26
    orr x0, x0, x27
    orr x0, x0, x28
    orr x0, x0, x29
    ret
// fn 13 touch_past(ws: cells, n: u64) -> u64 : read the 8 bytes just after x0's cell. With x0 the last cell of
// the workspace this is the first byte past it (unmapped): a CPU fault.
touch_past:
    ldr x0, [x0, #8]
    ret
