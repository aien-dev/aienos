/* Bare-metal entry for the QEMU virt NVMe payload. QEMU -kernel enters at
 * EL1 (no EL3 firmware), MMU and caches off. Set the stack, zero .bss, call
 * payload_main, then PSCI SYSTEM_OFF through HVC (QEMU's built-in PSCI). */
    .section .text.start, "ax"
    .global _start
_start:
    ldr x0, =__stack_top
    mov sp, x0
    ldr x0, =__bss_start
    ldr x1, =__bss_end
1:  cmp x0, x1
    b.hs 2f
    str xzr, [x0], #8
    b 1b
2:  bl payload_main
    ldr x0, =0x84000008
    hvc #0
3:  wfi
    b 3b
