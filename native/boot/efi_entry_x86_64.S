/* efi_entry_x86_64.S -- UEFI entry of an AIENOS x86_64 image (AIENOS-IMAC-BOOT-0).
 * Firmware calls _start(ImageHandle, SystemTable) in long mode with the
 * Microsoft x64 convention (RCX, RDX; UEFI 2.10 section 2.3.4). The image is
 * linked at 0 and loaded anywhere: apply our R_X86_64_RELATIVE relocations
 * against the load address, zero .bss, then call efi_main (built -mabi=ms).
 * Only volatile registers (RAX, RCX, RDX, R8-R11) are touched before the call.
 * This runs exactly once per load. */
    .section .text.entry, "ax"
    .global _start
    .type _start, @function
_start:
    push %rbp
    mov %rsp, %rbp
    push %rcx
    push %rdx
    lea __image_base(%rip), %r8         /* load address == link offset 0 */
    lea __rela_start(%rip), %r9
    lea __rela_end(%rip), %r10
1:  cmp %r10, %r9
    jae 3f
    mov 8(%r9), %rax                    /* r_info */
    mov %eax, %eax                      /* type: low 32 bits */
    add $24, %r9
    cmp $8, %rax                        /* R_X86_64_RELATIVE */
    jne 2f
    mov -8(%r9), %r11                   /* r_addend */
    add %r8, %r11
    mov -24(%r9), %rcx                  /* r_offset */
    mov %r11, (%r8,%rcx)
    jmp 1b
2:  test %rax, %rax                     /* R_X86_64_NONE */
    jz 1b
    movabs $0x8000000000000001, %rax    /* unexpected relocation type: EFI_LOAD_ERROR */
    mov %rbp, %rsp
    pop %rbp
    ret
3:  lea __bss_start(%rip), %r9
    lea __bss_end(%rip), %r10
4:  cmp %r10, %r9
    jae 5f
    movq $0, (%r9)
    add $8, %r9
    jmp 4b
5:  pop %rdx
    pop %rcx
    sub $32, %rsp                       /* shadow space; RSP stays 16-byte aligned */
    call efi_main
    mov %rbp, %rsp
    pop %rbp
    ret
    .size _start, . - _start
    .section .note.GNU-stack, "", @progbits
