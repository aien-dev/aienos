/* dma_window.c -- see dma_window.h and ADR 0020.
 * software-only DMA confinement (Pi 5, weaker than the Spark). */
#include "dma_window.h"

/* TEST-only mutants (make dma-window-mutants): each removes one check and
 * must make test_dma_window FAIL. Host builds only; never part of an image. */
#if defined(CK_DMAW_MUTANT_NO_END) || defined(CK_DMAW_MUTANT_WRAP) || \
    defined(CK_DMAW_MUTANT_NO_ZERO) || defined(CK_DMAW_MUTANT_NO_LATCH) || defined(CK_DMAW_MUTANT_NO_STALE) || \
    defined(CK_DMAW_MUTANT_NO_ALIGN) || defined(CK_DMAW_MUTANT_NO_FRAMECAP) || defined(CK_DMAW_MUTANT_NO_GOT) || \
    defined(CK_DMAW_MUTANT_NO_INDEX)
#if !__STDC_HOSTED__
#error "CK_DMAW_MUTANT_* are host test mutants only"
#endif
#ifdef CK_HARDWARE_STAGING
#error "CK_DMAW_MUTANT_* cannot be combined with CK_HARDWARE_STAGING"
#endif
#endif

static int pow2(uint64_t n) { return n != 0 && (n & (n - 1)) == 0; }

int ck_dmaw_init(struct ck_dmaw *w, void *mem, uint64_t bus_base, uint64_t size)
{
    if (!w)
        return CK_DMAW_E_PARAM;
    w->latched = 1; /* stay halted unless init fully succeeds */
    w->last_err = CK_DMAW_E_PARAM;
    w->base = 0;
    w->size = 0;
    w->next = 0;
    if (!mem || !pow2(size) || size < CK_DMAW_MIN_BYTES || size > CK_DMAW_MAX_BYTES)
        return CK_DMAW_E_PARAM;
    if ((bus_base & (size - 1)) != 0 || bus_base > UINT64_MAX - size)
        return CK_DMAW_E_PARAM; /* base must be aligned to size and not wrap */
    volatile uint8_t *p = (volatile uint8_t *)mem;
    for (uint64_t i = 0; i < size; i++)
        p[i] = 0;
    w->base = bus_base;
    w->size = size;
    w->latched = 0;
    w->last_err = CK_DMAW_OK;
    return CK_DMAW_OK;
}

static int latch(struct ck_dmaw *w, int err)
{
#ifndef CK_DMAW_MUTANT_NO_LATCH
    w->latched = 1;
#endif
    w->last_err = err;
    return err;
}

int ck_dmaw_halted(const struct ck_dmaw *w) { return !w || w->latched; }

int ck_dmaw_validate_aligned(struct ck_dmaw *w, uint64_t addr, uint64_t len, uint64_t align)
{
    (void)align; /* unused only in the NO_ALIGN mutant */
    if (!w)
        return CK_DMAW_E_PARAM;
    if (w->latched)
        return CK_DMAW_E_LATCHED;
#ifndef CK_DMAW_MUTANT_NO_ZERO
    if (len == 0)
        return latch(w, CK_DMAW_E_ZERO);
#endif
#ifndef CK_DMAW_MUTANT_NO_ALIGN
    if (!pow2(align) || (addr & (align - 1)) != 0)
        return latch(w, CK_DMAW_E_ALIGN);
#endif
#ifdef CK_DMAW_MUTANT_WRAP
    /* mutant: the naive end computation that wraps */
    if (addr < w->base || addr + len > w->base + w->size)
        return latch(w, CK_DMAW_E_RANGE);
#else
    int bad = 0;
    bad |= addr < w->base;
    bad |= len > w->size; /* also guarantees size - len cannot underflow */
#ifndef CK_DMAW_MUTANT_NO_END
    if (!bad)
        bad |= (addr - w->base) > (w->size - len);
#endif
    if (bad)
        return latch(w, CK_DMAW_E_RANGE);
#endif
    return CK_DMAW_OK;
}

int ck_dmaw_validate(struct ck_dmaw *w, uint64_t addr, uint64_t len)
{
    return ck_dmaw_validate_aligned(w, addr, len, 1);
}

int ck_dmaw_alloc(struct ck_dmaw *w, uint64_t len, uint64_t align, uint64_t *addr)
{
    if (!w || !addr || len == 0 || !pow2(align))
        return CK_DMAW_E_PARAM;
    if (w->latched)
        return CK_DMAW_E_LATCHED;
    uint64_t off = (w->next + (align - 1)) & ~(align - 1);
    if (off < w->next || off > w->size || len > w->size - off)
        return CK_DMAW_E_NOSPACE;
    w->next = off + len;
    *addr = w->base + off;
    return CK_DMAW_OK;
}

int ck_dmaw_ring_init(struct ck_dmaw_ring *r, struct ck_dmaw_slot *slots, uint32_t n)
{
    if (!r || !slots || n == 0 || n > CK_DMAW_RING_MAX || (n & (n - 1)) != 0)
        return CK_DMAW_E_PARAM;
    r->slots = slots;
    r->n = n;
    r->head = 0;
    r->inflight = 0;
    for (uint32_t i = 0; i < n; i++) {
        slots[i].d.addr = 0;
        slots[i].d.len = 0;
        slots[i].d.flags = 0;
        slots[i].state = CK_DMAW_SLOT_FREE;
    }
    return CK_DMAW_OK;
}

int ck_dmaw_ring_post(struct ck_dmaw_ring *r, struct ck_dmaw *w, uint64_t addr, uint32_t len,
                      uint32_t flags, uint32_t *idx)
{
    if (!r || !w || !idx)
        return CK_DMAW_E_PARAM;
    if (w->latched)
        return CK_DMAW_E_LATCHED;
#ifndef CK_DMAW_MUTANT_NO_FRAMECAP
    if (len > CK_DMAW_MAX_FRAME)
        return latch(w, CK_DMAW_E_BIG);
#endif
    int rc = ck_dmaw_validate_aligned(w, addr, len, CK_DMAW_BUF_ALIGN);
    if (rc != CK_DMAW_OK)
        return rc;
    struct ck_dmaw_slot *s = &r->slots[r->head];
    if (s->state != CK_DMAW_SLOT_FREE)
        return CK_DMAW_E_NOSPACE;
    s->d.addr = addr;
    s->d.len = len;
    s->d.flags = flags;
    s->state = CK_DMAW_SLOT_INFLIGHT;
    *idx = r->head;
    r->head = (r->head + 1) & (r->n - 1);
    r->inflight++;
    return CK_DMAW_OK;
}

int ck_dmaw_ring_emit(const struct ck_dmaw_ring *r, struct ck_dmaw *w, uint32_t idx,
                      struct ck_dmaw_desc *out)
{
    if (!r || !w || !out)
        return CK_DMAW_E_PARAM;
    if (w->latched)
        return CK_DMAW_E_LATCHED;
    if (idx >= r->n)
        return latch(w, CK_DMAW_E_INDEX);
    const struct ck_dmaw_slot *s = &r->slots[idx];
#ifndef CK_DMAW_MUTANT_NO_STALE
    if (s->state != CK_DMAW_SLOT_INFLIGHT)
        return latch(w, CK_DMAW_E_STALE);
#endif
    /* defence in depth: the shadow itself is checked again before it leaves */
    int rc = ck_dmaw_validate_aligned(w, s->d.addr, s->d.len, CK_DMAW_BUF_ALIGN);
    if (rc != CK_DMAW_OK)
        return rc;
    *out = s->d;
    return CK_DMAW_OK;
}

int ck_dmaw_ring_complete(struct ck_dmaw_ring *r, struct ck_dmaw *w, uint32_t idx, uint32_t got)
{
    (void)got; /* unused only in the NO_GOT mutant */
    if (!r || !w)
        return CK_DMAW_E_PARAM;
    if (w->latched)
        return CK_DMAW_E_LATCHED;
#ifndef CK_DMAW_MUTANT_NO_INDEX
    if (idx >= r->n)
        return latch(w, CK_DMAW_E_INDEX);
#endif
    struct ck_dmaw_slot *s = &r->slots[idx & (r->n - 1)];
#ifndef CK_DMAW_MUTANT_NO_STALE
    if (s->state != CK_DMAW_SLOT_INFLIGHT)
        return latch(w, CK_DMAW_E_STALE);
#endif
#ifndef CK_DMAW_MUTANT_NO_GOT
    if (got > s->d.len)
        return latch(w, CK_DMAW_E_RANGE);
#endif
    s->state = CK_DMAW_SLOT_FREE;
    if (r->inflight)
        r->inflight--;
    return CK_DMAW_OK;
}
