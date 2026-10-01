/* efi_entry.S -- UEFI entry of the AIENOS C kernel image (AArch64).
 * Firmware calls _start(ImageHandle, SystemTable) at its own EL (EL2 on QEMU
 * virtualization=on and on Machine 1) with its translation and stack. The
 * image is linked at 0 and loaded anywhere: apply our R_AARCH64_RELATIVE
 * relocations against the load address, zero .bss, then call efi_main.
 * This runs exactly once per load. */
    .section .text.entry, "ax"
    .global _start
    .type _start, %function
_start:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    stp x0, x1, [sp, #16]
    adrp x2, __image_base
    add x2, x2, :lo12:__image_base      /* load address == link offset 0 */
    adrp x3, __rela_start
    add x3, x3, :lo12:__rela_start
    adrp x4, __rela_end
    add x4, x4, :lo12:__rela_end
1:  cmp x3, x4
    b.hs 3f
    ldp x5, x6, [x3]                    /* r_offset, r_info */
    ldr x7, [x3, #16]                   /* r_addend */
    add x3, x3, #24
    and x6, x6, #0xffffffff
    cmp x6, #1027                       /* R_AARCH64_RELATIVE */
    b.ne 2f
    add x7, x7, x2
    str x7, [x2, x5]
    b 1b
2:  cbz x6, 1b                          /* R_AARCH64_NONE */
    mov x0, #0x8000000000000000         /* unexpected relocation type: */
    add x0, x0, #1                      /* return EFI_LOAD_ERROR */
    ldp x29, x30, [sp], #32
    ret
3:  adrp x3, __bss_start
    add x3, x3, :lo12:__bss_start
    adrp x4, __bss_end
    add x4, x4, :lo12:__bss_end
4:  cmp x3, x4
    b.hs 5f
    str xzr, [x3], #8
    b 4b
5:  ldp x0, x1, [sp, #16]
    bl efi_main
    ldp x29, x30, [sp], #32
    ret
    .size _start, . - _start
