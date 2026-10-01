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

/* Calls fn(lo, hi, ctx) with the byte span [lo, hi) of the RSDP (its checked
 * length), the XSDT/RSDT and every table the root lists (at least the 36-byte
 * header each, whatever their checksums). Used to keep all of them out of the
 * frame allocator; the caller rounds to pages. Returns the number of spans,
 * -1 if the RSDP is invalid (nothing reported). The root is reported even
 * when its own checksum fails; its entries are then not trusted. */
int ck_acpi_spans(uint64_t rsdp, void (*fn)(uint64_t lo, uint64_t hi, void *ctx), void *ctx);

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

/* CPU topology from the MADT GICC entries (acpi.rs madt_cpu_topology): enabled
 * or online-capable cores, (efficiency class, count) pairs sorted by class,
 * cores whose entry is too short (< 77 bytes) to carry a class. Pure parse;
 * nothing here starts a core. 0 ok, -1 malformed. */
#define CK_MAX_CLASSES 8
struct ck_cpu_topology {
    uint32_t cores;
    uint8_t class_id[CK_MAX_CLASSES];
    uint32_t class_count[CK_MAX_CLASSES];
    unsigned distinct_classes;
    uint32_t unknown_class;
    int has_first_mpidr;
    uint64_t first_mpidr;
};
int ck_madt_cpu_topology(const void *madt, struct ck_cpu_topology *out);
/* MPIDR affinity fields of every enabled or online-capable GICC entry (offset
 * 68, masked to Aff3 [39:32] and Aff2..Aff0 [23:0]), in table order, for the
 * SMP bring-up (core/smp.c). *n gets the number of such entries even when it
 * exceeds max (only the first max are stored). 0 ok, -1 malformed (bad entry
 * length, truncation, a GICC entry shorter than 76 bytes), -2 more than max. */
#define CK_MPIDR_AFF_MASK 0xff00ffffffull
int ck_madt_mpidrs(const void *madt, uint64_t *out, unsigned max, unsigned *n);
/* thread.rs place_task: task_index modulo the classified cores, walked class
 * by class. 0 and (class, index within class), or -1 if no core is classified. */
int ck_place_task(const struct ck_cpu_topology *t, uint32_t task_index, uint8_t *class_id,
                  uint32_t *core);

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

/* IORT (Arm IO Remapping Table): the first SMMUv3 node and the PCI root
 * complex ID mappings that point at it (ported from the Rust
 * aienos-kernel acpi::iort_smmuv3). */
#define CK_IORT_MAX_MAPS 8
struct ck_iort_map {
    uint32_t input_base, id_count, output_base; /* id_count = number of IDs - 1 */
};
struct ck_iort_smmu {
    uint64_t base;      /* SMMUv3 register base */
    uint32_t node_off;  /* offset of the SMMUv3 node in the table */
    uint32_t nmaps;
    struct ck_iort_map map[CK_IORT_MAX_MAPS];
};
/* 1 found, 0 no SMMUv3 node, -1 malformed (bad signature, truncation, a
 * node or mapping array outside the table, base 0, more than
 * CK_IORT_MAX_MAPS mappings to the SMMU). */
int ck_iort_parse(const void *iort, struct ck_iort_smmu *out);
/* Stream ID for PCI requester id `rid` (bus<<8 | dev<<3 | fn); 0 ok, -1 if
 * no mapping covers it. */
int ck_iort_stream_id(const struct ck_iort_smmu *s, uint32_t rid, uint32_t *sid);

#endif
