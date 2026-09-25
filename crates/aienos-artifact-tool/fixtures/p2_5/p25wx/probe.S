// P2-5 W^X probe: stores to its own code page. Code is mapped EL0 RX, so
// the store must take a permission fault and the kernel must terminate and
// reclaim the task. Reaching SYS_EXIT(0x57) would mean W^X was violated.
    .text
    .global _start
_start:
    adr     x9, 0f
0:  str     x9, [x9]
    mov     x0, #0x57
    mov     x8, #2
    svc     #0
1:  b       1b
