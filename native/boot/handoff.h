/* handoff.h -- what the AIENOS UEFI boot stub passes to the C kernel core
 * after ExitBootServices. Everything referenced here lives in memory the
 * frame allocator never hands out (the loaded image, LoaderData, ACPI). */
#ifndef AIENOS_CK_HANDOFF_H
#define AIENOS_CK_HANDOFF_H

#include <stdint.h>

#define CK_HANDOFF_MAGIC 0x31464f444e414843ull /* "CHANDOF1" */

struct ck_handoff {
    uint64_t magic;
    uint32_t firmware_el;      /* CurrentEL at UEFI entry (2 on QEMU virtualization=on) */
    uint32_t desc_version;
    uint64_t firmware_ttbr0;   /* TTBR0_EL2 (or EL1) firmware translated with */
    uint64_t firmware_sctlr;   /* SCTLR_EL2 (or EL1) of the firmware regime */
    uint64_t rsdp;             /* ACPI 2.0 RSDP physical address, 0 if absent */
    uint64_t memory_map;       /* copy of the final UEFI memory map */
    uint64_t map_size;
    uint64_t desc_size;
    uint64_t image_base;       /* loaded PE image, [base, end) */
    uint64_t image_end;
    uint64_t counter_freq_hz;
    uint64_t uefi_entry_ticks;
    uint32_t exit_attempts;    /* ExitBootServices calls until success */
    uint32_t reserved0;
    const char *commit;
};

/* Kernel core entry, still at the firmware EL with firmware translation. */
__attribute__((noreturn)) void ck_kernel_entry(struct ck_handoff *h);

#endif
