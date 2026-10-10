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
 * aienos-kernel acpi::iort_smmuv3). Each mapping keeps the PCI segment of
 * its root complex: a requester id (bus<<8 | dev<<3 | fn) only means
 * something inside one segment, so a lookup is (segment, rid).
 * The mapping array is sized by the table: a parse counts the mappings
 * that point at the SMMU and refuses the whole table (-1) when there are
 * more than CK_IORT_MAX_MAPS. 32 covers the DGX Spark (MEASURED: 15 root
 * complexes, one mapping each, to the first SMMUv3) with headroom. */
#define CK_IORT_MAX_MAPS 32
struct ck_iort_map {
    uint32_t segment;   /* PCI segment number of the root complex */
    uint32_t input_base, id_count, output_base; /* id_count = number of IDs - 1 */
};
/* Root complex mappings that target an SMMUv3 node other than the first
 * (aienos#286 cut B5/B6: on the DGX Spark, MEASURED 2026-10-10, segment 15,
 * the GB10's, maps to the second SMMUv3 at 0x13000000). The kernel does not
 * drive those SMMUs; it records the mapping so a requester behind one is
 * reported as CK_SMMU_OTHER (base and stream named) instead of "no stream".
 * CK_IORT_MAX_SMMUS bounds the SMMUv3 nodes remembered in a parse (Spark:
 * 3) and CK_IORT_MAX_OTHER the mappings to them (Spark: 1). */
#define CK_IORT_MAX_SMMUS 8
#define CK_IORT_MAX_OTHER 8
struct ck_iort_other {
    struct ck_iort_map map;
    uint64_t smmu_base; /* register base of the SMMUv3 node the mapping targets */
    uint32_t smmu_off;  /* offset of that node in the table */
};
/* Every SMMUv3 node of the table in table order (aienos#286 cut B7a): index
 * 0 is the first node (`base`, `node_off` above repeat it); the kernel may
 * bring up any of them (core/smmu_svc.c keeps one instance per entry). */
struct ck_iort_node {
    uint64_t base;
    uint32_t off;
};
/* IORT RMR node (type 6, reserved memory ranges; ACPICA actbl2.h
 * acpi_iort_rmr: flags u32 @16, rmr_count u32 @20, rmr_offset u32 @24;
 * acpi_iort_rmr_desc: base_address u64, length u64, reserved u32, 20 bytes
 * each). One entry per ID mapping of the node: the mapping names the SMMUv3
 * and the inclusive StreamID range (output_base .. output_base + id_count,
 * as Linux iort.c iort_rmr_alloc_sids reads it) whose transactions the
 * firmware expects to reach these ranges untranslated. flags: bit 0 remap
 * permitted, bit 1 privileged, bits [9:2] access attributes (ACPICA
 * ACPI_IORT_RMR_ATTR_*: 4 = Normal Non-cacheable, 5 = Normal IWB-OWB, 0..3
 * Device). On the DGX Spark (MEASURED 2026-10-10, docs/GB10_IORT_DECODE.md)
 * one RMR node, flags 0x10 (Normal NC, remap not permitted), streams
 * 0x0..=0x100 of the second SMMUv3 (0x13000000), three ranges:
 * 0x280000000+2 GiB, 0x300000000+48 MiB, 0xa1600000+386 MiB. */
#define CK_IORT_MAX_RMR 4        /* RMR (node, mapping) pairs remembered (Spark: 1) */
#define CK_IORT_MAX_RMR_RANGES 4 /* ranges per RMR node (Spark: 3) */
#define CK_IORT_RMR_REMAP_PERMITTED 1u
#define CK_IORT_RMR_PRIVILEGED 2u
#define CK_IORT_RMR_ATTR(flags) (((flags) >> 2) & 0xffu)
#define CK_IORT_RMR_ATTR_NORMAL_NC 4u
#define CK_IORT_RMR_ATTR_NORMAL_IWB_OWB 5u
struct ck_iort_rmr_range {
    uint64_t base, len;
};
struct ck_iort_rmr {
    uint32_t node_off;        /* the RMR node */
    uint32_t smmu_index;      /* index into ck_iort_smmu.smmus */
    uint32_t sid_lo, sid_hi;  /* inclusive StreamID range on that SMMU */
    uint32_t flags;
    uint32_t nranges;
    struct ck_iort_rmr_range range[CK_IORT_MAX_RMR_RANGES];
};
struct ck_iort_smmu {
    uint64_t base;      /* SMMUv3 register base (= smmus[0].base) */
    uint32_t node_off;  /* offset of the SMMUv3 node in the table (= smmus[0].off) */
    uint32_t nmaps;
    struct ck_iort_map map[CK_IORT_MAX_MAPS];
    uint32_t nother;
    struct ck_iort_other other[CK_IORT_MAX_OTHER];
    uint32_t nsmmus;
    struct ck_iort_node smmus[CK_IORT_MAX_SMMUS];
    uint32_t nrmr;
    struct ck_iort_rmr rmr[CK_IORT_MAX_RMR];
};
/* 1 found, 0 no SMMUv3 node, -1 malformed (bad signature, truncation, a
 * node or mapping array outside the table, base 0, a root complex node
 * too short to carry its segment number, more than CK_IORT_MAX_MAPS
 * mappings to the SMMU, more than CK_IORT_MAX_SMMUS SMMUv3 nodes or
 * CK_IORT_MAX_OTHER mappings to the other SMMUs, or two mappings to the
 * SMMU whose input ranges overlap in the same segment: an ambiguous
 * requester id is refused, not resolved by table order). A mapping to a
 * node that is not an SMMUv3 (an ITS group) is neither a stream nor an
 * "other" entry. */
int ck_iort_parse(const void *iort, struct ck_iort_smmu *out);
/* Stream ID for PCI requester id `rid` (bus<<8 | dev<<3 | fn) in PCI
 * segment `segment`; 0 ok, -1 if no mapping of that segment covers it. A
 * mapping of another segment never matches. */
int ck_iort_stream_id(const struct ck_iort_smmu *s, uint32_t segment, uint32_t rid, uint32_t *sid);
/* Same lookup over the mappings to SMMUs this kernel does not drive: 0 and
 * the stream id plus that SMMU's register base when (segment, rid) is
 * covered by one of them, -1 otherwise. Never consulted for granting a
 * window; it only names what refuses the requester. */
int ck_iort_other_stream(const struct ck_iort_smmu *s, uint32_t segment, uint32_t rid, uint32_t *sid,
                         uint64_t *smmu_base);
/* Route for PCI requester (segment, rid) (aienos#286 cut B7a): which SMMUv3
 * node (index into s->smmus, base, offset) and StreamID it reaches, through
 * the first-node mappings or the other-SMMU mappings, plus every RMR entry
 * that covers that stream on that SMMU (pointers into s). 0 found, -1 no
 * mapping covers the requester. Pure: reads the parse only. */
struct ck_iort_route {
    uint32_t smmu_index;
    uint64_t smmu_base;
    uint32_t smmu_off;
    uint32_t sid;
    uint32_t nrmr;
    const struct ck_iort_rmr *rmr[CK_IORT_MAX_RMR];
};
int ck_iort_route(const struct ck_iort_smmu *s, uint32_t segment, uint32_t rid, struct ck_iort_route *out);
/* RMR entries covering stream `sid` of the SMMUv3 node at table offset
 * `smmu_off` (used for named components, whose target the IORT names by
 * node). Fills out->rmr/nrmr only (and smmu_index when the node is known);
 * returns that count. */
uint32_t ck_iort_rmr_for(const struct ck_iort_smmu *s, uint32_t smmu_off, uint32_t sid, struct ck_iort_route *out);

/* IORT named component (node type 1) whose device object name has the same
 * final segment as `name` ("USB0" matches "\\_SB_.USB0"). out gets the node
 * name, the stream id of its single (or one-id) mapping to an SMMUv3 node,
 * and that SMMUv3 node (offset, register base). target_off == 0: no such
 * mapping (no stream for this device). Returns 1 found, 0 no such node, -1
 * malformed (signature, truncation, node, name or mapping outside the
 * table), -2 ambiguous (two named components with that final segment). */
struct ck_iort_named {
    char name[48];
    uint32_t node_off, nmaps;
    uint32_t stream_id;
    uint32_t target_off; /* SMMUv3 node the stream belongs to, 0 if none */
    uint64_t target_base;
};
int ck_iort_named(const void *iort, const char *name, struct ck_iort_named *out);

#endif
