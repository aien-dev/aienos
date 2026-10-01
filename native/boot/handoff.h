/* handoff.h -- what the AIENOS UEFI boot stub passes to the C kernel core
 * after ExitBootServices. Everything referenced here lives in memory the
 * frame allocator never hands out (the loaded image, LoaderData, ACPI). */
#ifndef AIENOS_CK_HANDOFF_H
#define AIENOS_CK_HANDOFF_H

#include <stdint.h>
#include <stddef.h>

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

/* Layout pins for the frozen CHANDOF1 v1 record (docs/BOOT_HANDOFF_CONTRACT.md
 * section 3, LP64): a reorder, resize or new field fails the build. */
_Static_assert(sizeof(struct ck_handoff) == 112, "ck_handoff size");
_Static_assert(offsetof(struct ck_handoff, magic) == 0, "ck_handoff.magic offset");
_Static_assert(offsetof(struct ck_handoff, firmware_el) == 8, "ck_handoff.firmware_el offset");
_Static_assert(offsetof(struct ck_handoff, desc_version) == 12, "ck_handoff.desc_version offset");
_Static_assert(offsetof(struct ck_handoff, firmware_ttbr0) == 16, "ck_handoff.firmware_ttbr0 offset");
_Static_assert(offsetof(struct ck_handoff, firmware_sctlr) == 24, "ck_handoff.firmware_sctlr offset");
_Static_assert(offsetof(struct ck_handoff, rsdp) == 32, "ck_handoff.rsdp offset");
_Static_assert(offsetof(struct ck_handoff, memory_map) == 40, "ck_handoff.memory_map offset");
_Static_assert(offsetof(struct ck_handoff, map_size) == 48, "ck_handoff.map_size offset");
_Static_assert(offsetof(struct ck_handoff, desc_size) == 56, "ck_handoff.desc_size offset");
_Static_assert(offsetof(struct ck_handoff, image_base) == 64, "ck_handoff.image_base offset");
_Static_assert(offsetof(struct ck_handoff, image_end) == 72, "ck_handoff.image_end offset");
_Static_assert(offsetof(struct ck_handoff, counter_freq_hz) == 80, "ck_handoff.counter_freq_hz offset");
_Static_assert(offsetof(struct ck_handoff, uefi_entry_ticks) == 88, "ck_handoff.uefi_entry_ticks offset");
_Static_assert(offsetof(struct ck_handoff, exit_attempts) == 96, "ck_handoff.exit_attempts offset");
_Static_assert(offsetof(struct ck_handoff, reserved0) == 100, "ck_handoff.reserved0 offset");
_Static_assert(offsetof(struct ck_handoff, commit) == 104, "ck_handoff.commit offset");

/* Kernel core entry, still at the firmware EL with firmware translation. */
__attribute__((noreturn)) void ck_kernel_entry(struct ck_handoff *h);

#endif
