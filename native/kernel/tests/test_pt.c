/* test_pt.c -- page-table builder: build real 4 KiB-granule tables in host
 * memory, then walk them independently (not through ck_pt_lookup) and check
 * output addresses, memory types, permissions, block sizes and guard holes. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ck_test.h"
#include "pt.h"

static int allocs, alloc_limit = 1 << 30;
static void *pool[4096];

static int host_alloc(void *ctx, uint64_t *phys)
{
    (void)ctx;
    if (allocs >= alloc_limit || allocs >= 4096)
        return -1;
    void *p = aligned_alloc(4096, 4096);
    if (!p)
        return -1;
    memset(p, 0xee, 4096); /* the builder must clear what it uses */
    pool[allocs++] = p;
    *phys = (uint64_t)(uintptr_t)p;
    return 0;
}

/* Independent walk: returns leaf descriptor and level, 0 if unmapped. */
static uint64_t walk(uint64_t root, uint64_t va, int *level)
{
    uint64_t t = root;
    for (int l = 0; l <= 3; l++) {
        unsigned idx = (va >> (39 - 9 * l)) & 511;
        uint64_t e = ((uint64_t *)(uintptr_t)t)[idx];
        if (!(e & 1))
            return 0;
        if (l == 3) {
            if (!(e & 2))
                return 0; /* level-3 type must be "page" */
            *level = 3;
            return e;
        }
        if (!(e & 2)) { /* block */
            if (l == 0)
                return 0;
            *level = l;
            return e;
        }
        t = e & CK_PTE_ADDR;
    }
    return 0;
}

static uint64_t out_pa(uint64_t e, int level, uint64_t va)
{
    uint64_t size = level == 1 ? 1ull << 30 : level == 2 ? 1ull << 21 : 1ull << 12;
    return (e & CK_PTE_ADDR & ~(size - 1)) | (va & (size - 1));
}

#define ATTR(e) ((e) & (CK_PTE_ATTRIDX(7) | CK_PTE_AP_RO | (1ull << 6) | CK_PTE_SH_INNER | CK_PTE_AF | CK_PTE_PXN | CK_PTE_UXN))

static void expect(uint64_t root, uint64_t va, uint64_t pa, uint64_t attrs, int level)
{
    int l = -1;
    uint64_t e = walk(root, va, &l);
    CHECK(e != 0);
    if (!e)
        return;
    CHECK(out_pa(e, l, va) == pa);
    CHECK(ATTR(e) == attrs);
    if (level)
        CHECK(l == level);
    if (out_pa(e, l, va) != pa || ATTR(e) != attrs || (level && l != level))
        printf("    va=0x%llx got pa=0x%llx attr=0x%llx level=%d\n", (unsigned long long)va,
               (unsigned long long)out_pa(e, l, va), (unsigned long long)ATTR(e), l);
}

static void expect_hole(uint64_t root, uint64_t va)
{
    int l;
    CHECK(walk(root, va, &l) == 0);
}

int main(void)
{
    struct ck_pt pt;
    CHECK(ck_pt_init(&pt, host_alloc, 0) == 0);
    uint64_t G = 1ull << 30, M2 = 2ull << 20, K4 = 4096;

    /* 3 GiB of RAM at 1 GiB: 1 GiB blocks. */
    CHECK(ck_pt_map(&pt, G, G, 3 * G, CK_PT_NORMAL_RW) == 0);
    expect(pt.root, G + 0x1234, G + 0x1234, CK_PT_NORMAL_RW, 1);
    expect(pt.root, 4 * G - 8, 4 * G - 8, CK_PT_NORMAL_RW, 1);
    expect_hole(pt.root, 4 * G);
    expect_hole(pt.root, 0x08000000);

    /* Image inside the RAM: splits the 1 GiB block down to pages. */
    uint64_t img = G + 0x200000 + 0x3000;
    CHECK(ck_pt_map(&pt, img, img, 0x5000, CK_PT_NORMAL_RX) == 0);
    CHECK(ck_pt_map(&pt, img + 0x5000, img + 0x5000, 0x2000, CK_PT_NORMAL_RO) == 0);
    expect(pt.root, img, img, CK_PT_NORMAL_RX, 3);
    expect(pt.root, img + 0x5000, img + 0x5000, CK_PT_NORMAL_RO, 3);
    expect(pt.root, img - K4, img - K4, CK_PT_NORMAL_RW, 3);
    expect(pt.root, img + 0x7000, img + 0x7000, CK_PT_NORMAL_RW, 3);
    expect(pt.root, G + 0x400000, G + 0x400000, CK_PT_NORMAL_RW, 2); /* neighbour 2 MiB block */
    expect(pt.root, 2 * G, 2 * G, CK_PT_NORMAL_RW, 1);                /* other GiB untouched */
    /* Text is executable at EL1 only, everything else is never executable. */
    { int l; uint64_t e = walk(pt.root, img, &l); CHECK(e && !(e & CK_PTE_PXN) && (e & CK_PTE_UXN) && (e & CK_PTE_AP_RO)); }
    { int l; uint64_t e = walk(pt.root, img + 0x5000, &l); CHECK(e && (e & CK_PTE_PXN) && (e & CK_PTE_AP_RO)); }
    { int l; uint64_t e = walk(pt.root, G, &l); CHECK(e && (e & CK_PTE_PXN) && !(e & CK_PTE_AP_RO)); }

    /* Guard holes: stack guard below, heap guards on both sides. */
    uint64_t stack = 2 * G + 0x10000;
    CHECK(ck_pt_unmap(&pt, stack, K4) == 0);
    expect_hole(pt.root, stack);
    expect_hole(pt.root, stack + K4 - 1);
    expect(pt.root, stack + K4, stack + K4, CK_PT_NORMAL_RW, 3);
    expect(pt.root, stack - K4, stack - K4, CK_PT_NORMAL_RW, 3);
    uint64_t heap = 3 * G, hsz = 16ull << 20;
    CHECK(ck_pt_unmap(&pt, heap - K4, K4) == 0 && ck_pt_unmap(&pt, heap + hsz, K4) == 0);
    expect_hole(pt.root, heap - K4);
    expect_hole(pt.root, heap + hsz);
    expect(pt.root, heap, heap, CK_PT_NORMAL_RW, 0);
    expect(pt.root, heap + hsz - 8, heap + hsz - 8, CK_PT_NORMAL_RW, 0);
    expect(pt.root, heap + M2, heap + M2, CK_PT_NORMAL_RW, 2);

    /* DMA pool non-cacheable, MMIO device. */
    uint64_t dma = G + 0x10000000;
    CHECK(ck_pt_map(&pt, dma, dma, 8ull << 20, CK_PT_NORMAL_NC) == 0);
    expect(pt.root, dma + 0x123456, dma + 0x123456, CK_PT_NORMAL_NC, 2);
    CHECK(ck_pt_map(&pt, 0x09000000, 0x09000000, K4, CK_PT_DEVICE) == 0);
    expect(pt.root, 0x09000010, 0x09000010, CK_PT_DEVICE, 3);
    expect_hole(pt.root, 0x09001000);

    /* Live tables: new mappings into empty space are fine, identical remaps
     * are accepted, anything needing break-before-make is refused. */
    pt.live = 1;
    CHECK(ck_pt_map(&pt, 0x08000000, 0x08000000, 0x10000, CK_PT_DEVICE) == 0);
    expect(pt.root, 0x0800fff8, 0x0800fff8, CK_PT_DEVICE, 3);
    CHECK(ck_pt_map(&pt, 0x09000000, 0x09000000, K4, CK_PT_DEVICE) == 0);
    CHECK(ck_pt_map(&pt, 0x09000000, 0x09000000, K4, CK_PT_NORMAL_RW) == CK_PT_ELIVE);
    CHECK(ck_pt_map(&pt, 2 * G + 0x400000, 2 * G + 0x400000, K4, CK_PT_DEVICE) == CK_PT_ELIVE);
    CHECK(ck_pt_unmap(&pt, 2 * G + 0x400000, K4) == CK_PT_ELIVE);
    expect(pt.root, 2 * G + 0x400000, 2 * G + 0x400000, CK_PT_NORMAL_RW, 2); /* block split by the stack guard */
    pt.live = 0;

    /* ck_pt_lookup agrees with the independent walk. */
    uint64_t pa, at;
    int lv;
    CHECK(ck_pt_lookup(&pt, img + 0x10, &pa, &at, &lv) == 0 && pa == img + 0x10 && lv == 3);
    CHECK(ck_pt_lookup(&pt, stack, &pa, &at, &lv) == -1);

    /* Bad arguments and table exhaustion. */
    CHECK(ck_pt_map(&pt, 0x1001, 0x1001, K4, CK_PT_DEVICE) == CK_PT_EINVAL);
    CHECK(ck_pt_map(&pt, 1ull << 48, 0, K4, CK_PT_DEVICE) == CK_PT_EINVAL);
    alloc_limit = allocs;
    CHECK(ck_pt_map(&pt, 0x200000000000ull, 0x10000000, K4, CK_PT_DEVICE) == CK_PT_ENOMEM);
    CHECK(pt.tables == (unsigned)allocs);
    for (int i = 0; i < allocs; i++)
        free(pool[i]);
    return ck_t_verdict("CK_PT");
}
