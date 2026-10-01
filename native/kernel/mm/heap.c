/* heap.c -- see heap.h. */
#include "heap.h"

#define HDR 16u
#define MAGIC_USED 0xa1e05ed0u
#define MAGIC_FREE 0xa1e0f4eeu

struct blk {
    uint64_t size;  /* whole block incl. header, multiple of 16 */
    uint32_t magic;
    uint32_t pad;
};

static struct blk *at(const struct ck_heap *h, size_t off) { return (struct blk *)(h->base + off); }

int ck_heap_init(struct ck_heap *h, void *base, size_t size)
{
    uintptr_t b = ((uintptr_t)base + 15) & ~(uintptr_t)15;
    size_t lost = b - (uintptr_t)base;
    if (size < lost + 2 * HDR)
        return -1;
    h->base = (uint8_t *)b;
    h->size = (size - lost) & ~(size_t)15;
    struct blk *f = at(h, 0);
    f->size = h->size;
    f->magic = MAGIC_FREE;
    f->pad = 0;
    return 0;
}

void *ck_heap_alloc(struct ck_heap *h, size_t bytes)
{
    if (!h->base || bytes > h->size)
        return 0;
    size_t need = ((bytes + 15) & ~(size_t)15) + HDR;
    if (need < 2 * HDR)
        need = 2 * HDR;
    for (size_t off = 0; off < h->size;) {
        struct blk *b = at(h, off);
        if (b->magic == MAGIC_FREE && b->size >= need) {
            if (b->size - need >= 2 * HDR) {
                struct blk *rest = at(h, off + need);
                rest->size = b->size - need;
                rest->magic = MAGIC_FREE;
                rest->pad = 0;
                b->size = need;
            }
            b->magic = MAGIC_USED;
            uint8_t *p = (uint8_t *)b + HDR;
            for (size_t i = 0; i < b->size - HDR; i++)
                p[i] = 0;
            return p;
        }
        if (!b->size)
            return 0; /* corrupted */
        off += b->size;
    }
    return 0;
}

int ck_heap_free(struct ck_heap *h, void *p)
{
    uint8_t *u = p;
    if (!p || u < h->base + HDR || u >= h->base + h->size || ((uintptr_t)u & 15))
        return -1;
    /* Find the block by walking, so a forged pointer is never trusted. */
    size_t prev = (size_t)-1;
    for (size_t off = 0; off < h->size;) {
        struct blk *b = at(h, off);
        if (!b->size)
            return -1;
        if ((uint8_t *)b + HDR == u) {
            if (b->magic != MAGIC_USED)
                return -1;
            b->magic = MAGIC_FREE;
            size_t next = off + b->size;
            if (next < h->size && at(h, next)->magic == MAGIC_FREE)
                b->size += at(h, next)->size;
            if (prev != (size_t)-1 && at(h, prev)->magic == MAGIC_FREE)
                at(h, prev)->size += b->size;
            return 0;
        }
        prev = off;
        off += b->size;
    }
    return -1;
}

size_t ck_heap_free_bytes(const struct ck_heap *h)
{
    size_t s = 0;
    for (size_t off = 0; off < h->size;) {
        struct blk *b = at(h, off);
        if (!b->size)
            break;
        if (b->magic == MAGIC_FREE)
            s += b->size - HDR;
        off += b->size;
    }
    return s;
}

int ck_heap_check(const struct ck_heap *h)
{
    size_t off = 0;
    while (off < h->size) {
        struct blk *b = at(h, off);
        if (b->size < 2 * HDR || (b->size & 15) || (b->magic != MAGIC_USED && b->magic != MAGIC_FREE))
            return -1;
        off += b->size;
    }
    return off == h->size ? 0 : -1;
}
