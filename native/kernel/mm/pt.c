/* pt.c -- see pt.h. Descriptors: table/page = 0b11, block = 0b01. */
#include "pt.h"

#define DESC_VALID 1ull
#define DESC_TABLE 2ull /* table at levels 0-2, page at level 3 */
#define ATTR_MASK (~CK_PTE_ADDR & ~3ull)

static uint64_t *tbl(uint64_t phys) { return (uint64_t *)(uintptr_t)phys; }
static unsigned shift_of(int level) { return 39u - 9u * (unsigned)level; }

static int new_table(struct ck_pt *pt, uint64_t *phys)
{
    if (pt->alloc(pt->ctx, phys) || (*phys & 0xfff) || (*phys & ~CK_PTE_ADDR))
        return CK_PT_ENOMEM;
    uint64_t *t = tbl(*phys);
    for (int i = 0; i < 512; i++)
        t[i] = 0;
    pt->tables++;
    return 0;
}

int ck_pt_init(struct ck_pt *pt, int (*alloc)(void *, uint64_t *), void *ctx)
{
    pt->alloc = alloc;
    pt->ctx = ctx;
    pt->live = 0;
    pt->tables = 0;
    return new_table(pt, &pt->root);
}

static int is_table(uint64_t e, int level) { return level < 3 && (e & 3) == 3; }

/* Replace a block at `level` with a next-level table mapping the same range
 * with the same attributes. */
static int split(struct ck_pt *pt, uint64_t *slot, int level)
{
    uint64_t e = *slot, t;
    if (pt->live)
        return CK_PT_ELIVE;
    int r = new_table(pt, &t);
    if (r)
        return r;
    int child = level + 1;
    uint64_t csize = 1ull << shift_of(child);
    uint64_t base = e & CK_PTE_ADDR & ~((1ull << shift_of(level)) - 1);
    uint64_t attrs = e & ATTR_MASK;
    uint64_t kind = child == 3 ? 3ull : 1ull;
    for (int i = 0; i < 512; i++)
        tbl(t)[i] = (base + (uint64_t)i * csize) | attrs | kind;
    *slot = t | 3ull;
    return 0;
}

/* Does the valid leaf `e` at `level` already map va..va+n -> pa.. with attrs? */
static int leaf_matches(uint64_t e, int level, uint64_t va, uint64_t pa, uint64_t attrs)
{
    uint64_t size = 1ull << shift_of(level);
    uint64_t base = e & CK_PTE_ADDR & ~(size - 1);
    return (e & ATTR_MASK) == attrs && base + (va & (size - 1)) == pa;
}

static int map_level(struct ck_pt *pt, uint64_t table, int level, uint64_t va, uint64_t pa,
                     uint64_t len, uint64_t attrs)
{
    unsigned sh = shift_of(level);
    uint64_t size = 1ull << sh;
    while (len) {
        uint64_t *slot = &tbl(table)[(va >> sh) & 511];
        uint64_t chunk_end = (va & ~(size - 1)) + size;
        uint64_t n = chunk_end - va < len ? chunk_end - va : len;
        uint64_t e = *slot;
        if (level == 3) {
            uint64_t d = pa | attrs | 3ull;
            if (pt->live && (e & DESC_VALID) && e != d)
                return CK_PT_ELIVE;
            *slot = d;
        } else if (level >= 1 && !(va & (size - 1)) && !(pa & (size - 1)) && n == size &&
                   !is_table(e, level)) {
            uint64_t d = pa | attrs | 1ull;
            if (pt->live && (e & DESC_VALID) && e != d)
                return CK_PT_ELIVE;
            *slot = d;
        } else {
            if (!(e & DESC_VALID)) {
                uint64_t t;
                int r = new_table(pt, &t);
                if (r)
                    return r;
                *slot = t | 3ull;
            } else if (!is_table(e, level)) {
                if (pt->live && leaf_matches(e, level, va, pa, attrs))
                    goto next; /* already mapped exactly so */
                int r = split(pt, slot, level);
                if (r)
                    return r;
            }
            int r = map_level(pt, *slot & CK_PTE_ADDR, level + 1, va, pa, n, attrs);
            if (r)
                return r;
        }
    next:
        va += n;
        pa += n;
        len -= n;
    }
    return 0;
}

int ck_pt_map(struct ck_pt *pt, uint64_t va, uint64_t pa, uint64_t len, uint64_t attrs)
{
    if ((va | pa | len) & 0xfff || !len || (attrs & ~ATTR_MASK) || va + len - 1 > 0xffffffffffffull ||
        pa + len - 1 > 0xffffffffffffull)
        return CK_PT_EINVAL;
    return map_level(pt, pt->root, 0, va, pa, len, attrs);
}

static int unmap_level(struct ck_pt *pt, uint64_t table, int level, uint64_t va, uint64_t len)
{
    unsigned sh = shift_of(level);
    uint64_t size = 1ull << sh;
    while (len) {
        uint64_t *slot = &tbl(table)[(va >> sh) & 511];
        uint64_t chunk_end = (va & ~(size - 1)) + size;
        uint64_t n = chunk_end - va < len ? chunk_end - va : len;
        uint64_t e = *slot;
        if (e & DESC_VALID) {
            if (level == 3 || (!is_table(e, level) && n == size)) {
                *slot = 0;
            } else {
                if (!is_table(e, level)) {
                    int r = split(pt, slot, level);
                    if (r)
                        return r;
                }
                int r = unmap_level(pt, *slot & CK_PTE_ADDR, level + 1, va, n);
                if (r)
                    return r;
            }
        }
        va += n;
        len -= n;
    }
    return 0;
}

int ck_pt_unmap(struct ck_pt *pt, uint64_t va, uint64_t len)
{
    if ((va | len) & 0xfff || !len)
        return CK_PT_EINVAL;
    return unmap_level(pt, pt->root, 0, va, len);
}

int ck_pt_lookup(const struct ck_pt *pt, uint64_t va, uint64_t *pa, uint64_t *attrs, int *level)
{
    uint64_t table = pt->root;
    for (int l = 0; l <= 3; l++) {
        uint64_t e = tbl(table)[(va >> shift_of(l)) & 511];
        if (!(e & DESC_VALID))
            return -1;
        if (l == 0 && !is_table(e, 0))
            return -1; /* no level-0 blocks with a 4 KiB granule */
        if (is_table(e, l)) {
            table = e & CK_PTE_ADDR;
            continue;
        }
        if (l == 3 && (e & 3) != 3)
            return -1; /* reserved encoding */
        uint64_t size = 1ull << shift_of(l);
        if (pa)
            *pa = (e & CK_PTE_ADDR & ~(size - 1)) | (va & (size - 1));
        if (attrs)
            *attrs = e & ATTR_MASK;
        if (level)
            *level = l;
        return 0;
    }
    return -1;
}
