/* acpi.h -- ACPI table lookup and the MADT/SPCR/FADT fields the core uses.
 * Pure functions over memory (identity mapped in the kernel, host buffers in
 * the tests). Every table is length- and checksum-checked before use. */
#ifndef AIENOS_CK_ACPI_H
#define AIENOS_CK_ACPI_H

#include <stddef.h>
#include <stdint.h>

#define CK_ACPI_SDT_HEADER 36u

/* Sum of bytes is zero. */
int ck_acpi_sum_ok(const void *p, size_t len);

/* Validates an ACPI 2.0+ RSDP (signature, 20-byte and extended checksum)
 * and returns the XSDT address it names, or 0. Revision 0 RSDPs return the
 * RSDT address with *is_xsdt = 0. */
uint64_t ck_acpi_root(uint64_t rsdp, int *is_xsdt);

/* First table with this signature listed in the XSDT/RSDT that passes the
 * length and checksum checks; NULL if none. */
const void *ck_acpi_lookup(uint64_t rsdp, const char sig[4]);

/* Calls fn(table, len, ctx) for every table the root lists (no checksum
 * filter; used to map the tables). Returns the number listed, -1 if the
 * RSDP/root is invalid. */
int ck_acpi_each(uint64_t rsdp, void (*fn)(uint64_t table, uint32_t len, void *ctx), void *ctx);

struct ck_madt_gic {
    uint64_t gicd;        /* GICD base (type 0x0C) */
    uint32_t gic_version; /* GICD entry field, 0 = "discover from hardware" */
    uint64_t gicr;        /* first GICR discovery range (type 0x0E) */
    uint32_t gicr_len;
    uint32_t gicc_count;  /* enabled or online-capable GICC entries */
    uint64_t gicc_gicr;   /* GICR base from the first GICC, if no 0x0E range */
};
/* 0 on success, -1 on a malformed table (bad entry length, truncation). */
int ck_madt_parse(const void *madt, struct ck_madt_gic *out);

struct ck_spcr {
    uint8_t interface_type; /* 0x03 PL011, 0x0d/0x0e SBSA, 0x00/0x12 16550 */
    uint8_t space;          /* GAS address space: 0 = system memory */
    uint8_t bit_width;
    uint8_t access_size;    /* GAS access size: 1 byte .. 4 qword */
    uint64_t base;
};
int ck_spcr_parse(const void *spcr, struct ck_spcr *out);

/* FADT ARM_BOOT_ARCH flags: bit 0 PSCI compliant, bit 1 PSCI uses HVC.
 * -1 if the FADT is too short to carry the field. */
int ck_fadt_arm_boot_arch(const void *fadt, uint16_t *flags);

#endif
