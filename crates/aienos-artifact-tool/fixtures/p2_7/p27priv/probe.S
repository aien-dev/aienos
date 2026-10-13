// PI5-7 cut 3 privileged-instruction probe: AArch64 EL0, position independent, no relocations. It reads
// SCTLR_EL1, a system register that EL0 may not access (Arm ARM DDI 0487: MRS of an EL1 register from EL0 is
// UNDEFINED, taken to EL1 with ESR_EL1.EC 0x00 unknown reason, or EC 0x18 when the access is trapped). The task
// is terminated and reclaimed and the kernel keeps running. Reaching SYS_EXIT(0x57) would mean EL0 may read
// kernel control registers.
    .text
    .global _start
_start:
    mrs     x0, sctlr_el1
    mov     x0, #0x57
    mov     x8, #2
    svc     #0
1:  b       1b
