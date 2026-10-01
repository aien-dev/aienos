/* frames.c -- see frames.h. */
#include "frames.h"

static uint64_t up(uint64_t v, uint64_t a) { return (v + a - 1) & ~(a - 1); }
static uint64_t down(uint64_t v, uint64_t a) { return v & ~(a - 1); }

void ck_frames_init(struct ck_frames *f)
{
    f->n = 0;
    f->dropped = 0;
}

static int insert_at(struct ck_frames *f, unsigned i, uint64_t base, uint64_t end)
{
    if (f->n >= CK_FRAMES_MAX) {
        f->dropped++;
        return -1;
    }
    for (unsigned j = f->n; j > i; j--)
        f->r[j] = f->r[j - 1];
    f->r[i].base = base;
    f->r[i].end = end;
    f->n++;
    return 0;
}

static void remove_at(struct ck_frames *f, unsigned i)
{
    for (unsigned j = i; j + 1 < f->n; j++)
        f->r[j] = f->r[j + 1];
    f->n--;
}

int ck_frames_add(struct ck_frames *f, uint64_t base, uint64_t end)
{
    base = up(base, CK_PAGE);
    end = down(end, CK_PAGE);
    if (end <= base)
        return 0;
    /* Drop any part already free (overlaps are a caller bug; stay sane). */
    ck_frames_reserve(f, base, end);
    unsigned i = 0;
    while (i < f->n && f->r[i].base < base)
        i++;
    /* Merge with predecessor / successor when they touch. */
    if (i > 0 && f->r[i - 1].end == base) {
        f->r[i - 1].end = end;
        if (i < f->n && f->r[i].base == end) {
            f->r[i - 1].end = f->r[i].end;
            remove_at(f, i);
        }
        return 0;
    }
    if (i < f->n && f->r[i].base == end) {
        f->r[i].base = base;
        return 0;
    }
    return insert_at(f, i, base, end);
}

void ck_frames_reserve(struct ck_frames *f, uint64_t base, uint64_t end)
{
    base = down(base, CK_PAGE);
    end = up(end, CK_PAGE);
    if (end <= base)
        return;
    for (unsigned i = 0; i < f->n;) {
        struct ck_frange *r = &f->r[i];
        if (r->end <= base || r->base >= end) {
            i++;
            continue;
        }
        if (r->base >= base && r->end <= end) {
            remove_at(f, i);
            continue;
        }
        if (r->base < base && r->end > end) {
            uint64_t tail = r->end;
            r->end = base;
            if (insert_at(f, i + 1, end, tail))
                return; /* table full: the tail is lost, never handed out */
            i += 2;
            continue;
        }
        if (r->base < base)
            r->end = base;
        else
            r->base = end;
        i++;
    }
}

int ck_frames_from_efi(struct ck_frames *f, const void *map, uint64_t map_size, uint64_t desc_size)
{
    if (!map || desc_size < sizeof(struct ck_efi_desc))
        return -1;
    int added = 0;
    for (uint64_t off = 0; off + desc_size <= map_size; off += desc_size) {
        const struct ck_efi_desc *d = (const struct ck_efi_desc *)((const uint8_t *)map + off);
        if (d->type != CK_EFI_CONVENTIONAL || !d->pages || d->pages > (1ull << 36))
            continue;
        uint64_t end = d->phys + d->pages * CK_PAGE;
        if (end < d->phys)
            continue;
        if (ck_frames_add(f, d->phys, end) == 0)
            added++;
    }
    return added;
}

int ck_frames_alloc(struct ck_frames *f, uint64_t npages, uint64_t align, uint64_t *out)
{
    if (!npages || align < CK_PAGE || (align & (align - 1)))
        return -1;
    uint64_t size = npages * CK_PAGE;
    for (unsigned i = 0; i < f->n; i++) {
        struct ck_frange *r = &f->r[i];
        uint64_t a = up(r->base, align);
        if (a < r->base || a >= r->end || r->end - a < size)
            continue;
        uint64_t head_base = r->base, tail_base = a + size, tail_end = r->end;
        if (head_base == a && tail_base == tail_end) {
            remove_at(f, i);
        } else if (head_base == a) {
            r->base = tail_base;
        } else if (tail_base == tail_end) {
            r->end = a;
        } else {
            if (f->n >= CK_FRAMES_MAX)
                continue; /* cannot split here; try a later range */
            r->end = a;
            insert_at(f, i + 1, tail_base, tail_end);
        }
        *out = a;
        return 0;
    }
    return -1;
}

void ck_frames_free(struct ck_frames *f, uint64_t base, uint64_t npages)
{
    ck_frames_add(f, base, base + npages * CK_PAGE);
}

uint64_t ck_frames_free_bytes(const struct ck_frames *f)
{
    uint64_t s = 0;
    for (unsigned i = 0; i < f->n; i++)
        s += f->r[i].end - f->r[i].base;
    return s;
}
