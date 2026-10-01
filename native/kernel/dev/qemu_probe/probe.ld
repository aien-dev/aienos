/* PROBE layout: 1 MiB stack (m5_envelope_open alone needs ~64 KiB, the
 * capability revoke ~23 KiB), heap from __heap_start to __heap_end. */
ENTRY(_start)
SECTIONS
{
    . = 0x40400000;
    .text : { *(.text.start) *(.text*) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    . = ALIGN(4096);
    __bss_start = .;
    .bss : { *(.bss*) *(COMMON) }
    . = ALIGN(16);
    __bss_end = .;
    . = . + 0x100000;
    . = ALIGN(16);
    __stack_top = .;
    . = ALIGN(4096);
    __heap_start = .;
    . = . + 0x4000000;
    __heap_end = .;
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
