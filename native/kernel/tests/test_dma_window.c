/* test_dma_window.c -- Pi 5 software-only DMA confinement (dev/dma_window.c,
 * ADR 0020). Hosted: this proves the rule's logic, NOT the hardware. Run
 * under ASan/UBSan and with each CK_DMAW_MUTANT_* (make dma-window-mutants),
 * where every mutant must make this test FAIL. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ck_test.h"
#include "dma_window.h"

#define WSIZE 65536u
#define WBASE 0x40000000ull

static uint8_t *mem;

static void fresh(struct ck_dmaw *w)
{
    memset(mem, 0xAA, WSIZE);
    CHECK(ck_dmaw_init(w, mem, WBASE, WSIZE) == CK_DMAW_OK);
}

static void t_init(void)
{
    struct ck_dmaw w;
    memset(mem, 0xAA, WSIZE);
    CHECK(ck_dmaw_init(&w, mem, WBASE, WSIZE) == CK_DMAW_OK);
    int zero = 1;
    for (uint32_t i = 0; i < WSIZE; i++) zero &= mem[i] == 0;
    CHECK(zero);
    CHECK(!ck_dmaw_halted(&w));
    CHECK(ck_dmaw_init(&w, mem, WBASE, WSIZE + 4096) == CK_DMAW_E_PARAM); /* not pow2 */
    CHECK(ck_dmaw_halted(&w));                                           /* failed init stays halted */
    CHECK(ck_dmaw_init(&w, mem, WBASE + 4096, WSIZE) == CK_DMAW_E_PARAM); /* misaligned base */
    CHECK(ck_dmaw_init(&w, mem, WBASE, CK_DMAW_MAX_BYTES * 2) == CK_DMAW_E_PARAM);
    CHECK(ck_dmaw_init(&w, mem, WBASE, 2048) == CK_DMAW_E_PARAM);
    CHECK(ck_dmaw_init(&w, mem, 0 - (uint64_t)WSIZE, WSIZE) == CK_DMAW_E_PARAM); /* end wraps */
    CHECK(ck_dmaw_init(&w, NULL, WBASE, WSIZE) == CK_DMAW_E_PARAM);
    CHECK(ck_dmaw_init(&w, mem, WBASE, WSIZE) == CK_DMAW_OK);
    CHECK(!ck_dmaw_halted(&w));
}

static void t_validate(void)
{
    struct ck_dmaw w;
    fresh(&w);
    CHECK(ck_dmaw_validate(&w, WBASE, 1) == CK_DMAW_OK);
    CHECK(ck_dmaw_validate(&w, WBASE, WSIZE) == CK_DMAW_OK);               /* whole window */
    CHECK(ck_dmaw_validate(&w, WBASE + WSIZE - 1, 1) == CK_DMAW_OK);       /* last byte */
    CHECK(!ck_dmaw_halted(&w));

    fresh(&w); /* below the window */
    CHECK(ck_dmaw_validate(&w, WBASE - 1, 16) == CK_DMAW_E_RANGE);
    CHECK(ck_dmaw_halted(&w));
    CHECK(ck_dmaw_validate(&w, WBASE, 1) == CK_DMAW_E_LATCHED); /* valid call after latch refused */

    fresh(&w); /* straddles the end */
    CHECK(ck_dmaw_validate(&w, WBASE + WSIZE - 8, 16) == CK_DMAW_E_RANGE);
    CHECK(ck_dmaw_halted(&w));

    fresh(&w); /* starts at the end */
    CHECK(ck_dmaw_validate(&w, WBASE + WSIZE, 1) == CK_DMAW_E_RANGE);

    fresh(&w); /* entirely above */
    CHECK(ck_dmaw_validate(&w, WBASE + WSIZE + 4096, 16) == CK_DMAW_E_RANGE);

    fresh(&w); /* wrapped length: addr + len overflows 2^64 to a small number */
    CHECK(ck_dmaw_validate(&w, 0 - 16ull, 64) == CK_DMAW_E_RANGE);
    fresh(&w);
    CHECK(ck_dmaw_validate(&w, WBASE + 16, 0 - 8ull) == CK_DMAW_E_RANGE); /* huge len wraps back inside */
    fresh(&w);
    CHECK(ck_dmaw_validate(&w, WBASE, UINT64_MAX) == CK_DMAW_E_RANGE);

    fresh(&w); /* zero length */
    CHECK(ck_dmaw_validate(&w, WBASE + 8, 0) == CK_DMAW_E_ZERO);
    CHECK(ck_dmaw_halted(&w));

    fresh(&w); /* misaligned */
    CHECK(ck_dmaw_validate_aligned(&w, WBASE + 4, 16, 8) == CK_DMAW_E_ALIGN);
    CHECK(ck_dmaw_halted(&w));
    fresh(&w);
    CHECK(ck_dmaw_validate_aligned(&w, WBASE + 8, 16, 8) == CK_DMAW_OK);
    CHECK(ck_dmaw_validate_aligned(&w, WBASE + 8, 16, 3) == CK_DMAW_E_ALIGN); /* align not pow2 */

    CHECK(ck_dmaw_init(&w, mem, WBASE, WSIZE) == CK_DMAW_OK); /* only init clears the latch */
    CHECK(!ck_dmaw_halted(&w));
}

static void t_alloc(void)
{
    struct ck_dmaw w;
    uint64_t a, b;
    fresh(&w);
    CHECK(ck_dmaw_alloc(&w, 100, 64, &a) == CK_DMAW_OK && a == WBASE);
    CHECK(ck_dmaw_alloc(&w, 8, 64, &b) == CK_DMAW_OK && b == WBASE + 128 && ck_dmaw_validate(&w, b, 8) == CK_DMAW_OK);
    CHECK(ck_dmaw_alloc(&w, WSIZE, 8, &a) == CK_DMAW_E_NOSPACE);
    CHECK(!ck_dmaw_halted(&w)); /* running out of space is not a violation */
    CHECK(ck_dmaw_alloc(&w, UINT64_MAX, 8, &a) == CK_DMAW_E_NOSPACE);
    CHECK(ck_dmaw_alloc(&w, 8, 3, &a) == CK_DMAW_E_PARAM);
    CHECK(ck_dmaw_alloc(&w, 0, 8, &a) == CK_DMAW_E_PARAM);
}

static void t_ring(void)
{
    struct ck_dmaw w;
    struct ck_dmaw_ring r;
    struct ck_dmaw_slot slots[4];
    struct ck_dmaw_desc d;
    uint32_t i, j;

    fresh(&w);
    CHECK(ck_dmaw_ring_init(&r, slots, 3) == CK_DMAW_E_PARAM);
    CHECK(ck_dmaw_ring_init(&r, slots, 4) == CK_DMAW_OK);
    CHECK(ck_dmaw_ring_post(&r, &w, WBASE + 64, 100, 7, &i) == CK_DMAW_OK && i == 0);
    CHECK(ck_dmaw_ring_emit(&r, &w, i, &d) == CK_DMAW_OK && d.addr == WBASE + 64 && d.len == 100 && d.flags == 7);
    CHECK(ck_dmaw_ring_complete(&r, &w, i, 100) == CK_DMAW_OK);
    CHECK(!ck_dmaw_halted(&w));

    /* stale: emit and complete of a slot no longer in flight */
    CHECK(ck_dmaw_ring_emit(&r, &w, i, &d) == CK_DMAW_E_STALE);
    CHECK(ck_dmaw_halted(&w));
    fresh(&w);
    ck_dmaw_ring_init(&r, slots, 4);
    ck_dmaw_ring_post(&r, &w, WBASE, 64, 0, &i);
    CHECK(ck_dmaw_ring_complete(&r, &w, i, 64) == CK_DMAW_OK);
    CHECK(ck_dmaw_ring_complete(&r, &w, i, 64) == CK_DMAW_E_STALE); /* double completion */
    CHECK(ck_dmaw_halted(&w));

    /* device reports more bytes than were posted */
    fresh(&w);
    ck_dmaw_ring_init(&r, slots, 4);
    ck_dmaw_ring_post(&r, &w, WBASE, 64, 0, &i);
    CHECK(ck_dmaw_ring_complete(&r, &w, i, 65) == CK_DMAW_E_RANGE);
    CHECK(ck_dmaw_halted(&w));

    /* device-supplied index out of range */
    fresh(&w);
    ck_dmaw_ring_init(&r, slots, 4);
    ck_dmaw_ring_post(&r, &w, WBASE, 64, 0, &i);
    CHECK(ck_dmaw_ring_complete(&r, &w, 4, 1) == CK_DMAW_E_INDEX);
    CHECK(ck_dmaw_halted(&w));
    fresh(&w);
    ck_dmaw_ring_init(&r, slots, 4);
    ck_dmaw_ring_post(&r, &w, WBASE, 64, 0, &i);
    CHECK(ck_dmaw_ring_emit(&r, &w, 99, &d) == CK_DMAW_E_INDEX);

    /* post: out of window, wrapped, zero, misaligned, jumbo; each latches */
    uint64_t bad_addr[] = {WBASE - 8, WBASE + WSIZE, WBASE + WSIZE - 8, 0 - 8ull};
    uint32_t bad_len[] = {64, 64, 64, 64};
    for (j = 0; j < 4; j++) {
        fresh(&w);
        ck_dmaw_ring_init(&r, slots, 4);
        CHECK(ck_dmaw_ring_post(&r, &w, bad_addr[j], bad_len[j], 0, &i) == CK_DMAW_E_RANGE);
        CHECK(ck_dmaw_halted(&w) && r.inflight == 0);
    }
    fresh(&w);
    ck_dmaw_ring_init(&r, slots, 4);
    CHECK(ck_dmaw_ring_post(&r, &w, WBASE, 0, 0, &i) == CK_DMAW_E_ZERO && ck_dmaw_halted(&w));
    fresh(&w);
    ck_dmaw_ring_init(&r, slots, 4);
    CHECK(ck_dmaw_ring_post(&r, &w, WBASE + 4, 64, 0, &i) == CK_DMAW_E_ALIGN && ck_dmaw_halted(&w));
    fresh(&w);
    ck_dmaw_ring_init(&r, slots, 4);
    CHECK(ck_dmaw_ring_post(&r, &w, WBASE, CK_DMAW_MAX_FRAME, 0, &i) == CK_DMAW_OK); /* max standard frame ok */
    fresh(&w);
    ck_dmaw_ring_init(&r, slots, 4);
    CHECK(ck_dmaw_ring_post(&r, &w, WBASE, CK_DMAW_MAX_FRAME + 1, 0, &i) == CK_DMAW_E_BIG && ck_dmaw_halted(&w));

    /* ring full is not a violation; a latched window refuses valid posts */
    fresh(&w);
    ck_dmaw_ring_init(&r, slots, 4);
    for (j = 0; j < 4; j++) CHECK(ck_dmaw_ring_post(&r, &w, WBASE + 64 * j, 64, 0, &i) == CK_DMAW_OK);
    CHECK(ck_dmaw_ring_post(&r, &w, WBASE, 64, 0, &i) == CK_DMAW_E_NOSPACE && !ck_dmaw_halted(&w));
    ck_dmaw_validate(&w, WBASE - 1, 1);
    CHECK(ck_dmaw_ring_post(&r, &w, WBASE, 64, 0, &i) == CK_DMAW_E_LATCHED);
    CHECK(ck_dmaw_ring_emit(&r, &w, 0, &d) == CK_DMAW_E_LATCHED);

    /* shadow, not ring memory: corrupting the shadow after post is caught at emit */
    fresh(&w);
    ck_dmaw_ring_init(&r, slots, 4);
    ck_dmaw_ring_post(&r, &w, WBASE, 64, 0, &i);
    slots[i].d.addr = WBASE + WSIZE + 8;
    CHECK(ck_dmaw_ring_emit(&r, &w, i, &d) == CK_DMAW_E_RANGE && ck_dmaw_halted(&w));
}

/* Property test: for hostile (addr,len), validate agrees with a 128-bit
 * reference, and every descriptor the ring emits is fully inside the window. */
static uint64_t rs = 0x9e3779b97f4a7c15ull;
static uint64_t rnd(void)
{
    rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17;
    return rs;
}

static void t_property(void)
{
    struct ck_dmaw w;
    struct ck_dmaw_ring r;
    struct ck_dmaw_slot slots[8];
    struct ck_dmaw_desc d;
    int mismatch = 0, escaped = 0, emitted = 0;
    for (int n = 0; n < 200000; n++) {
        uint64_t addr, len;
        switch (rnd() % 5) {
        case 0: addr = rnd(); len = rnd(); break;
        case 1: addr = WBASE + rnd() % (2 * WSIZE); len = rnd() % 4096; break;
        case 2: addr = (WBASE - 64) + rnd() % 128; len = 1 + rnd() % 64; break;
        case 3: addr = WBASE + WSIZE - 64 + rnd() % 128; len = rnd() % 128; break;
        default: addr = 0 - (rnd() % 256); len = rnd() % 512; break;
        }
        fresh(&w);
        int rc = ck_dmaw_validate(&w, addr, len);
        unsigned __int128 end = (unsigned __int128)addr + len;
        int inside = len != 0 && addr >= WBASE && end <= (unsigned __int128)WBASE + WSIZE;
        if ((rc == CK_DMAW_OK) != inside) mismatch++;
        ck_dmaw_ring_init(&r, slots, 8);
        uint32_t idx;
        if (ck_dmaw_ring_post(&r, &w, addr, (uint32_t)len, 0, &idx) == CK_DMAW_OK) {
            if (ck_dmaw_ring_emit(&r, &w, idx, &d) == CK_DMAW_OK) {
                emitted++;
                unsigned __int128 e = (unsigned __int128)d.addr + d.len;
                if (d.addr < WBASE || e > (unsigned __int128)WBASE + WSIZE || d.len == 0) escaped++;
            }
        }
    }
    CHECK(mismatch == 0);
    CHECK(escaped == 0);
    CHECK(emitted > 0);
}

int main(void)
{
    mem = malloc(WSIZE);
    if (!mem) return 2;
    t_init();
    t_validate();
    t_alloc();
    t_ring();
    t_property();
    free(mem);
    return ck_t_verdict("test_dma_window");
}
