// PI5-7 cut 3 kernel-read probe: AArch64 EL0, position independent, no relocations. It loads one 64-bit word
// from a kernel address (KADDR: by default 0x210000, the kernel's own translation-table root on the Raspberry Pi 5
// image, see the "mmu_switch: ... aienos_root=" line of every Pi run). The kernel maps its memory EL1-only in the
// task's table, so the load must take a permission fault from EL0 (ESR_EL1.EC 0x24, WnR 0, FAR = KADDR) and the
// kernel must terminate and reclaim the task and keep running. Reaching SYS_EXIT(0x57) would mean the load
// succeeded, i.e. kernel memory is readable from EL0.
// Assemble with: as --defsym KADDR=<address> (assemble.sh does).
    .ifndef KADDR
    .set KADDR, 0x210000
    .endif
    .text
    .global _start
_start:
    ldr     x9, =KADDR
    ldr     x0, [x9]
    mov     x0, #0x57
    mov     x8, #2
    svc     #0
1:  b       1b
