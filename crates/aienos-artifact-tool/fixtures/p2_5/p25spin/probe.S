// P2-5 runaway probe: never yields and never makes a syscall. Only the
// kernel's admitted elapsed/CPU budget can end it (timer IRQ from EL0).
    .text
    .global _start
_start:
0:  b       0b
