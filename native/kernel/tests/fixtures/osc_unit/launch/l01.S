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
