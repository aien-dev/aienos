/* image.ld -- AIENOS C kernel image layout. Linked position independent at
 * address 0 (ImageBase 0); the PE32+ header for UEFI is emitted here as data,
 * so file offset == RVA (FileAlignment == SectionAlignment == 4 KiB). The
 * entry stub applies the R_AARCH64_RELATIVE relocations itself (efi_entry.S),
 * so the PE base-relocation directory holds one no-op block only: it tells
 * the firmware the image may be loaded anywhere.
 *
 *   [0x0000 .head]  DOS stub + PE32+ header, padded to 4 KiB
 *   [.text]         code                    (our tables: RX)
 *   [.rodata ...]   rodata, relocs, GOT      (our tables: RO, XN)
 *   [.data .bss]    data, bss                (our tables: RW, XN)
 */
OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_start)

SECTIONS
{
    . = 0;
    __image_base = .;
    .head : {
        /* IMAGE_DOS_HEADER: "MZ", e_lfanew = 0x40 */
        SHORT(0x5a4d) . = 0x3c; LONG(0x40)
        /* PE signature */
        LONG(0x00004550)
        /* IMAGE_FILE_HEADER */
        SHORT(0xaa64)           /* Machine: ARM64 */
        SHORT(2)                /* NumberOfSections */
        LONG(0) LONG(0) LONG(0) /* TimeDateStamp, symbol table, symbols */
        SHORT(240)              /* SizeOfOptionalHeader */
        SHORT(0x0226)           /* EXECUTABLE | LINE_NUMS_STRIPPED | LARGE_ADDRESS | DEBUG_STRIPPED */
        /* IMAGE_OPTIONAL_HEADER64 */
        SHORT(0x020b)           /* PE32+ */
        BYTE(2) BYTE(42)        /* linker version (binutils 2.42, informational) */
        LONG(__text_end - __text_start)       /* SizeOfCode */
        LONG(__data_file_end - __data_start)  /* SizeOfInitializedData */
        LONG(__image_end - __data_file_end)   /* SizeOfUninitializedData */
        LONG(_start)            /* AddressOfEntryPoint (RVA) */
        LONG(__text_start)      /* BaseOfCode */
        QUAD(0)                 /* ImageBase */
        LONG(0x1000) LONG(0x1000) /* SectionAlignment, FileAlignment */
        SHORT(0) SHORT(0) SHORT(0) SHORT(0) SHORT(0) SHORT(0) /* OS, image, subsystem versions */
        LONG(0)                 /* Win32VersionValue */
        LONG(__image_end)       /* SizeOfImage */
        LONG(__text_start)      /* SizeOfHeaders */
        LONG(0)                 /* CheckSum */
        SHORT(10)               /* Subsystem: EFI application */
        SHORT(0)                /* DllCharacteristics */
        QUAD(0) QUAD(0) QUAD(0) QUAD(0) /* stack/heap reserve/commit */
        LONG(0)                 /* LoaderFlags */
        LONG(16)                /* NumberOfRvaAndSizes */
        QUAD(0) QUAD(0) QUAD(0) QUAD(0) QUAD(0) /* export, import, resource, exception, security */
        LONG(__pe_reloc) LONG(12)               /* base relocation directory */
        QUAD(0) QUAD(0) QUAD(0) QUAD(0) QUAD(0) QUAD(0) QUAD(0) QUAD(0) QUAD(0) QUAD(0)
        /* section table: .text */
        BYTE(0x2e) BYTE(0x74) BYTE(0x65) BYTE(0x78) BYTE(0x74) BYTE(0) BYTE(0) BYTE(0)
        LONG(__text_end - __text_start) LONG(__text_start)
        LONG(__text_end - __text_start) LONG(__text_start)
        LONG(0) LONG(0) SHORT(0) SHORT(0)
        LONG(0x60000020)        /* CODE | EXECUTE | READ */
        /* section table: .data (rodata, relocs, data; bss as VirtualSize tail) */
        BYTE(0x2e) BYTE(0x64) BYTE(0x61) BYTE(0x74) BYTE(0x61) BYTE(0) BYTE(0) BYTE(0)
        LONG(__image_end - __data_start) LONG(__data_start)
        LONG(__data_file_end - __data_start) LONG(__data_start)
        LONG(0) LONG(0) SHORT(0) SHORT(0)
        LONG(0xc0000040)        /* INITIALIZED_DATA | READ | WRITE */
        . = ALIGN(4096);
    }

    . = ALIGN(4096);
    __text_start = .;
    .text : { KEEP(*(.text.entry)) *(.text .text.*) }
    . = ALIGN(4096);
    __text_end = .;

    __data_start = .;
    __ro_start = .;
    .rodata : {
        *(.rodata .rodata.*)
        . = ALIGN(4);
        /* One base-relocation block with only IMAGE_REL_BASED_ABSOLUTE (no-op)
         * entries: valid, relocatable, nothing for the firmware to patch. */
        __pe_reloc = .;
        LONG(0) LONG(12) SHORT(0) SHORT(0)
    }
    . = ALIGN(8);
    .rela.dyn : { __rela_start = .; *(.rela .rela.*) __rela_end = .; }
    .dynamic : { *(.dynamic) }
    .dynsym : { *(.dynsym) }
    .dynstr : { *(.dynstr) }
    .hash : { *(.hash) }
    .gnu.hash : { *(.gnu.hash) }
    .data.rel.ro : { *(.data.rel.ro .data.rel.ro.*) }
    .got : { *(.got) *(.got.plt) }
    . = ALIGN(4096);
    __ro_end = .;

    __rw_start = .;
    .data : {
        *(.data .data.*)
        . = ALIGN(4096);
    }
    __data_file_end = .;
    .bss (NOLOAD) : ALIGN(16) {
        __bss_start = .;
        *(.bss .bss.*) *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }
    . = ALIGN(4096);
    __image_end = .;

    /DISCARD/ : { *(.interp) *(.comment) *(.note*) *(.eh_frame*) *(.plt) }
}
