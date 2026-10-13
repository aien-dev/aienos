// PI5-7 cut 3 kernel-write probe: AArch64 EL0, position independent, no relocations. It stores one 64-bit word
// to a kernel address (KADDR: by default 0x2000000, inside the kernel heap of the Raspberry Pi 5 image, which is
// 0x261000-0x4261000 and nearly all free at this point: a store that wrongly succeeded would not corrupt live
// data, it would only show). The kernel maps its memory EL1-only in the task's table, so the store must take a
// permission fault from EL0 (ESR_EL1.EC 0x24, WnR 1, FAR = KADDR), the task is terminated and reclaimed and the
// kernel keeps running. Reaching SYS_EXIT(0x57) would mean the store succeeded.
// Assemble with: as --defsym KADDR=<address> (assemble.sh does).
    .ifndef KADDR
    .set KADDR, 0x2000000
    .endif
    .text
    .global _start
_start:
    ldr     x9, =KADDR
    movz    x10, #0xdead
    str     x10, [x9]
    mov     x0, #0x57
    mov     x8, #2
    svc     #0
1:  b       1b
