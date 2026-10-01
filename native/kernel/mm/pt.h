/* pt.h -- AArch64 stage-1 translation tables, 4 KiB granule, 48-bit VA
 * (T0SZ = 16, walk starts at level 0). Identity use only in the kernel, but
 * the builder takes any va/pa. Table memory comes from a callback and is
 * addressed by its physical address (identity), so the host tests can build
 * and walk real tables in host memory. */
#ifndef AIENOS_CK_PT_H
#define AIENOS_CK_PT_H

#include <stdint.h>

/* MAIR_EL1 attribute indexes. */
#define CK_MAIR_IDX_NORMAL 0 /* 0xff Normal, inner/outer WB RA WA */
#define CK_MAIR_IDX_DEVICE 1 /* 0x04 Device-nGnRE */
#define CK_MAIR_IDX_NC 2     /* 0x44 Normal, inner/outer Non-cacheable */
#define CK_MAIR_VALUE 0x4404ffull

/* Leaf descriptor attribute bits. */
#define CK_PTE_ATTRIDX(i) ((uint64_t)(i) << 2)
#define CK_PTE_AP_RO (1ull << 7)    /* AP[2]: read-only; AP[1] = 0: no EL0 access */
#define CK_PTE_SH_INNER (3ull << 8)
#define CK_PTE_AF (1ull << 10)
#define CK_PTE_PXN (1ull << 53)
#define CK_PTE_UXN (1ull << 54)
#define CK_PTE_ADDR 0x0000fffffffff000ull

#define CK_PT_NORMAL_RW (CK_PTE_ATTRIDX(CK_MAIR_IDX_NORMAL) | CK_PTE_SH_INNER | CK_PTE_AF | CK_PTE_PXN | CK_PTE_UXN)
#define CK_PT_NORMAL_RO (CK_PT_NORMAL_RW | CK_PTE_AP_RO)
#define CK_PT_NORMAL_RX (CK_PTE_ATTRIDX(CK_MAIR_IDX_NORMAL) | CK_PTE_SH_INNER | CK_PTE_AF | CK_PTE_AP_RO | CK_PTE_UXN)
#define CK_PT_DEVICE (CK_PTE_ATTRIDX(CK_MAIR_IDX_DEVICE) | CK_PTE_AF | CK_PTE_PXN | CK_PTE_UXN)
#define CK_PT_NORMAL_NC (CK_PTE_ATTRIDX(CK_MAIR_IDX_NC) | CK_PTE_SH_INNER | CK_PTE_AF | CK_PTE_PXN | CK_PTE_UXN)

#define CK_PT_EINVAL (-1)
#define CK_PT_ENOMEM (-2)
#define CK_PT_ELIVE (-3) /* change would need break-before-make on live tables */

struct ck_pt {
    uint64_t root;                             /* level 0 table, physical */
    int (*alloc)(void *ctx, uint64_t *phys);   /* one zero-able 4 KiB frame */
    void *ctx;
    int live;      /* tables are in use: refuse to change valid entries */
    unsigned tables; /* tables allocated, root included */
};

int ck_pt_init(struct ck_pt *pt, int (*alloc)(void *, uint64_t *), void *ctx);
/* Maps [va, va+len) -> [pa, pa+len) with `attrs` (one of CK_PT_*), using
 * 1 GiB / 2 MiB blocks where aligned. Not live: overrides earlier mappings,
 * splitting blocks as needed. Live: only fills invalid entries (or accepts
 * identical ones), else CK_PT_ELIVE. */
int ck_pt_map(struct ck_pt *pt, uint64_t va, uint64_t pa, uint64_t len, uint64_t attrs);
/* Unmaps [va, va+len); splits blocks (not live only). */
int ck_pt_unmap(struct ck_pt *pt, uint64_t va, uint64_t len);
/* Walks va. 0 if mapped (pa, leaf attributes, leaf level 1..3), -1 if not. */
int ck_pt_lookup(const struct ck_pt *pt, uint64_t va, uint64_t *pa, uint64_t *attrs, int *level);

#endif
