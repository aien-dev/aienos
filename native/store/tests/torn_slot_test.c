/*
 * torn_slot_test.c -- host block-device emulation and exhaustive torn-write
 * fault injection for torn_slot.c.
 *
 * This is NOT QEMU and NOT a real SSD. The emulated device keeps a durable
 * image and records every write as individual logical-block writes, split
 * into flush epochs. A crash image is built from the durable image before the
 * commit plus a chosen fate for each block written in the epoch that was cut:
 * the block lands NEW, stays OLD, or is TORN inside the block. Epochs before
 * the cut are durable (FLUSH returned), epochs after it never happened.
 *
 * For every crash image the test runs recovery and asserts it returns the
 * complete old record or the complete new record, byte for byte, and never
 * anything else. It then commits a further record on the crash image and
 * asserts that one is recovered (a crash never wedges the region).
 */
#include "../torn_slot.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long long checks, failures;

#define CHECK(cond)                                                          \
    do {                                                                     \
        checks++;                                                            \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            if (failures < 20)                                               \
                fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                    \
    } while (0)

/* ---------------- emulated device ---------------- */

#define MAX_TRACE 64

typedef struct {
    uint64_t lba;    /* absolute block */
    uint32_t epoch;  /* flush epoch index within the traced operation */
    uint8_t *data;   /* block_size bytes */
} trace_write;

typedef struct {
    uint32_t bs;
    uint64_t nblocks;
    uint8_t *media;          /* what reads see (and, untraced, what is durable) */
    int tracing;
    uint32_t epoch;
    unsigned ntrace;
    trace_write trace[MAX_TRACE];
    unsigned long reads, writes, flushes;
    int fail_read_at;        /* -1 = never; else fail the Nth read */
} emu;

static int emu_read(void *ctx, uint64_t lba, uint32_t count, uint8_t *buf)
{
    emu *e = ctx;
    if (e->fail_read_at >= 0 && (unsigned long)e->fail_read_at == e->reads) { e->reads++; return 1; }
    e->reads++;
    if (lba + count > e->nblocks) return 1;
    memcpy(buf, e->media + lba * e->bs, (size_t)count * e->bs);
    return 0;
}

static int emu_write(void *ctx, uint64_t lba, uint32_t count, const uint8_t *buf)
{
    emu *e = ctx;
    e->writes++;
    if (lba + count > e->nblocks) return 1;
    for (uint32_t i = 0; i < count; i++) {
        if (e->tracing) {
            if (e->ntrace >= MAX_TRACE) abort();
            trace_write *t = &e->trace[e->ntrace++];
            t->lba = lba + i;
            t->epoch = e->epoch;
            t->data = malloc(e->bs);
            if (!t->data) abort();
            memcpy(t->data, buf + (size_t)i * e->bs, e->bs);
        }
        memcpy(e->media + (lba + i) * e->bs, buf + (size_t)i * e->bs, e->bs);
    }
    return 0;
}

static int emu_flush(void *ctx)
{
    emu *e = ctx;
    e->flushes++;
    if (e->tracing) e->epoch++;
    return 0;
}

static void emu_init(emu *e, uint32_t bs, uint64_t nblocks)
{
    memset(e, 0, sizeof *e);
    e->bs = bs;
    e->nblocks = nblocks;
    e->media = calloc(nblocks, bs);
    if (!e->media) abort();
    e->fail_read_at = -1;
}

static void emu_clear_trace(emu *e)
{
    for (unsigned i = 0; i < e->ntrace; i++) free(e->trace[i].data);
    e->ntrace = 0;
    e->epoch = 0;
    e->tracing = 0;
}

static ts_device emu_dev(emu *e)
{
    ts_device d = {e, e->bs, e->nblocks, emu_read, emu_write, emu_flush};
    return d;
}

/* ---------------- records ---------------- */

static uint64_t xs_state;
static uint64_t xs(void)
{
    xs_state ^= xs_state << 13;
    xs_state ^= xs_state >> 7;
    xs_state ^= xs_state << 17;
    return xs_state;
}

static void make_record(uint8_t *r, unsigned gen)
{
    /* gen 3 repeats gen 2 (same bytes, new seq); gen 4 is all zero. */
    if (gen == 4) { memset(r, 0, TS_RECORD_BYTES); return; }
    if (gen == 3) gen = 2;
    uint64_t s = 0x9E3779B97F4A7C15ull * (gen + 1);
    for (unsigned i = 0; i < TS_RECORD_BYTES; i++) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        r[i] = (uint8_t)(s >> 24);
    }
}

/* ---------------- crash images ---------------- */

enum { FATE_OLD = 0, FATE_NEW = 1, FATE_TORN_PREFIX = 2, FATE_TORN_WORDS = 3 };

typedef struct {
    uint32_t cut_epoch;       /* epoch in which power was cut */
    unsigned n;               /* writes in that epoch */
    uint8_t fate[MAX_TRACE];  /* per write in that epoch */
    uint32_t torn_bytes;      /* FATE_TORN_PREFIX: new bytes persisted from offset 0 */
    uint64_t word_seed;       /* FATE_TORN_WORDS: 8-byte words picked old/new */
} crash_spec;

/* Build the crash image into img from pre (durable before the commit) and
 * the trace in e. */
static void build_crash(const emu *e, const uint8_t *pre, uint8_t *img, const crash_spec *c)
{
    size_t bytes = (size_t)e->nblocks * e->bs;
    memcpy(img, pre, bytes);
    unsigned idx = 0;
    for (unsigned i = 0; i < e->ntrace; i++) {
        const trace_write *t = &e->trace[i];
        uint8_t *dst = img + t->lba * e->bs;
        if (t->epoch < c->cut_epoch) { memcpy(dst, t->data, e->bs); continue; }
        if (t->epoch > c->cut_epoch) continue;
        uint8_t fate = c->fate[idx++];
        if (fate == FATE_NEW) {
            memcpy(dst, t->data, e->bs);
        } else if (fate == FATE_TORN_PREFIX) {
            memcpy(dst, t->data, c->torn_bytes);
        } else if (fate == FATE_TORN_WORDS) {
            uint64_t s = c->word_seed | 1;
            for (uint32_t w = 0; w < e->bs; w += 8) {
                s ^= s << 13; s ^= s >> 7; s ^= s << 17;
                if (s & 1) memcpy(dst + w, t->data + w, 8);
            }
        }
    }
}

static unsigned epoch_writes(const emu *e, uint32_t epoch)
{
    unsigned n = 0;
    for (unsigned i = 0; i < e->ntrace; i++) n += e->trace[i].epoch == epoch;
    return n;
}

/* ---------------- one geometry campaign ---------------- */

typedef struct {
    unsigned long long cases, as_old, as_new, mixed, bad_code, relive_fail;
    unsigned long long prefix_cases, subset_cases, torn_prefix_cases, torn_word_cases, nested_cases;
} tally;

/* Recover from img and classify against old/new. old_gen 0 means "no record". */
static int classify(uint32_t bs, uint64_t nblocks, uint64_t base, uint8_t *img,
                    const uint8_t *oldr, unsigned old_gen, const uint8_t *newr,
                    unsigned new_gen, tally *t, int relive, unsigned relive_gen)
{
    emu v;
    memset(&v, 0, sizeof v);
    v.bs = bs; v.nblocks = nblocks; v.media = img; v.fail_read_at = -1;
    ts_device d = emu_dev(&v);
    ts_region r;
    uint8_t got[TS_RECORD_BYTES];
    uint64_t seq = 0;
    int outcome = -1; /* 0 old, 1 new */

    CHECK(ts_open(&r, &d, base) == TS_OK);
    int rc = ts_recover(&r, got, &seq, NULL);
    CHECK(v.writes == 0); /* recovery never writes */
    t->cases++;
    if (rc == TS_EMPTY && old_gen == 0) {
        outcome = 0;
    } else if (rc == TS_OK) {
        if (seq == old_gen && old_gen != 0 && memcmp(got, oldr, TS_RECORD_BYTES) == 0) outcome = 0;
        else if (seq == new_gen && memcmp(got, newr, TS_RECORD_BYTES) == 0) outcome = 1;
    }
    if (outcome == 0) t->as_old++;
    else if (outcome == 1) t->as_new++;
    else if (rc == TS_OK || rc == TS_EMPTY) { t->mixed++; CHECK(!"recovered neither complete old nor complete new"); }
    else { t->bad_code++; CHECK(!"recovery returned an error code after a crash"); }

    if (relive && outcome >= 0) {
        uint8_t rec[TS_RECORD_BYTES], back[TS_RECORD_BYTES];
        make_record(rec, relive_gen);
        rec[0] ^= 0x5A; rec[4095] ^= 0xA5; /* distinct from every campaign record */
        int ok = ts_commit(&r, rec) == TS_OK;
        ts_region r2;
        uint64_t s2 = 0;
        ok = ok && ts_open(&r2, &d, base) == TS_OK && ts_recover(&r2, back, &s2, NULL) == TS_OK;
        ok = ok && memcmp(back, rec, TS_RECORD_BYTES) == 0 && s2 == (outcome ? new_gen : old_gen) + 1;
        if (!ok) { t->relive_fail++; CHECK(!"commit after crash recovery did not stick"); }
    }
    return outcome;
}

static void run_crash(emu *e, const uint8_t *pre, uint8_t *img, const crash_spec *c,
                      uint64_t base, const uint8_t *oldr, unsigned old_gen,
                      const uint8_t *newr, unsigned new_gen, tally *t)
{
    build_crash(e, pre, img, c);
    classify(e->bs, e->nblocks, base, img, oldr, old_gen, newr, new_gen, t, 1, new_gen + 50);
}

static int campaign(uint32_t bs, uint64_t base, unsigned gens, int nested)
{
    uint64_t nblocks = base + (uint64_t)TS_UNITS * (TS_RECORD_BYTES / bs) + 3; /* spare blocks after */
    size_t bytes = (size_t)nblocks * bs;
    emu e;
    emu_init(&e, bs, nblocks);
    uint8_t *pre = malloc(bytes), *img = malloc(bytes), *img2 = malloc(bytes);
    uint8_t oldr[TS_RECORD_BYTES], newr[TS_RECORD_BYTES];
    if (!pre || !img || !img2) abort();
    /* Blocks outside the region carry a pattern that must never change. */
    for (size_t i = 0; i < bytes; i++) e.media[i] = (uint8_t)(0xC3 ^ i);
    memset(e.media + base * bs, 0, (size_t)TS_UNITS * TS_RECORD_BYTES);
    tally t;
    memset(&t, 0, sizeof t);

    ts_device d = emu_dev(&e);
    ts_region r;
    uint8_t got[TS_RECORD_BYTES];
    uint64_t seq;
    CHECK(ts_open(&r, &d, base) == TS_OK);
    CHECK(ts_recover(&r, got, &seq, NULL) == TS_EMPTY);
    memset(oldr, 0, sizeof oldr);

    for (unsigned g = 1; g <= gens; g++) {
        make_record(newr, g);
        memcpy(pre, e.media, bytes);
        e.tracing = 1;
        CHECK(ts_commit(&r, newr) == TS_OK);
        e.tracing = 0;
        /* The commit is exactly: one unit, FLUSH, one unit, FLUSH. */
        unsigned m = TS_RECORD_BYTES / bs;
        CHECK(e.ntrace == 2 * m && e.epoch == 2);
        CHECK(epoch_writes(&e, 0) == m && epoch_writes(&e, 1) == m);

        for (uint32_t ep = 0; ep < 2; ep++) {
            crash_spec c;
            memset(&c, 0, sizeof c);
            c.cut_epoch = ep;
            c.n = m;
            /* 1. Prefix cuts: the first k blocks landed, k = 0..m. */
            for (unsigned k = 0; k <= m; k++) {
                for (unsigned i = 0; i < m; i++) c.fate[i] = i < k ? FATE_NEW : FATE_OLD;
                run_crash(&e, pre, img, &c, base, oldr, g - 1, newr, g, &t);
                t.prefix_cases++;
            }
            /* 2. Every subset of the m blocks (reordered completion). */
            for (unsigned mask = 0; mask < (1u << m); mask++) {
                for (unsigned i = 0; i < m; i++) c.fate[i] = (mask >> i) & 1 ? FATE_NEW : FATE_OLD;
                run_crash(&e, pre, img, &c, base, oldr, g - 1, newr, g, &t);
                t.subset_cases++;
            }
            /* 3. Torn inside block k at every byte offset, blocks before k
             *    landed, blocks after k did not. */
            for (unsigned k = 0; k < m; k++) {
                for (uint32_t b = 1; b < bs; b++) {
                    for (unsigned i = 0; i < m; i++) c.fate[i] = i < k ? FATE_NEW : FATE_OLD;
                    c.fate[k] = FATE_TORN_PREFIX;
                    c.torn_bytes = b;
                    run_crash(&e, pre, img, &c, base, oldr, g - 1, newr, g, &t);
                    t.torn_prefix_cases++;
                }
            }
            /* 4. Torn inside block k as a scatter of 8-byte words, the other
             *    blocks a random subset. */
            for (unsigned k = 0; k < m; k++) {
                for (unsigned trial = 0; trial < 64; trial++) {
                    uint64_t rs = xs();
                    for (unsigned i = 0; i < m; i++) c.fate[i] = (rs >> i) & 1 ? FATE_NEW : FATE_OLD;
                    c.fate[k] = FATE_TORN_WORDS;
                    c.word_seed = xs();
                    run_crash(&e, pre, img, &c, base, oldr, g - 1, newr, g, &t);
                    t.torn_word_cases++;
                }
            }
        }

        /* 5. Double crash: crash the commit (prefix cut), recover, retry the
         *    same commit on the crash image and crash that too (prefix cut). */
        if (nested && g >= 2) {
            for (uint32_t ep1 = 0; ep1 < 2; ep1++) {
                for (unsigned k1 = 0; k1 <= m; k1++) {
                    crash_spec c1;
                    memset(&c1, 0, sizeof c1);
                    c1.cut_epoch = ep1; c1.n = m;
                    for (unsigned i = 0; i < m; i++) c1.fate[i] = i < k1 ? FATE_NEW : FATE_OLD;
                    build_crash(&e, pre, img, &c1);
                    emu v;
                    memset(&v, 0, sizeof v);
                    v.bs = bs; v.nblocks = nblocks; v.media = img2; v.fail_read_at = -1;
                    memcpy(img2, img, bytes);
                    ts_device vd = emu_dev(&v);
                    ts_region vr;
                    uint64_t s1 = 0;
                    CHECK(ts_open(&vr, &vd, base) == TS_OK);
                    int rc1 = ts_recover(&vr, got, &s1, NULL);
                    CHECK(rc1 == TS_OK);
                    if (s1 == g) continue; /* first crash already kept the new record */
                    CHECK(s1 == g - 1);
                    v.tracing = 1;
                    CHECK(ts_commit(&vr, newr) == TS_OK);
                    v.tracing = 0;
                    for (uint32_t ep2 = 0; ep2 < 2; ep2++) {
                        for (unsigned k2 = 0; k2 <= m; k2++) {
                            crash_spec c2;
                            memset(&c2, 0, sizeof c2);
                            c2.cut_epoch = ep2; c2.n = m;
                            for (unsigned i = 0; i < m; i++) c2.fate[i] = i < k2 ? FATE_NEW : FATE_OLD;
                            uint8_t *img3 = malloc(bytes);
                            if (!img3) abort();
                            build_crash(&v, img, img3, &c2);
                            classify(bs, nblocks, base, img3, oldr, g - 1, newr, g, &t, 0, 0);
                            t.nested_cases++;
                            free(img3);
                        }
                    }
                    emu_clear_trace(&v);
                }
            }
        }

        emu_clear_trace(&e);
        /* Live state still recovers the new record; outside blocks untouched. */
        {
            ts_region r3;
            CHECK(ts_open(&r3, &d, base) == TS_OK);
            CHECK(ts_recover(&r3, got, &seq, NULL) == TS_OK);
            CHECK(seq == g && memcmp(got, newr, TS_RECORD_BYTES) == 0);
            for (size_t i = 0; i < bytes; i++) {
                if (i >= base * bs && i < base * bs + (size_t)TS_UNITS * TS_RECORD_BYTES) continue;
                if (e.media[i] != (uint8_t)(0xC3 ^ i)) { CHECK(!"write outside the region"); break; }
            }
        }
        memcpy(oldr, newr, sizeof oldr);
    }

    printf("  bs=%u base_lba=%" PRIu64 " gens=%u: cases=%llu (prefix=%llu subset=%llu torn_prefix=%llu "
           "torn_words=%llu nested=%llu) as_old=%llu as_new=%llu mixed=%llu error=%llu relive_fail=%llu\n",
           bs, base, gens, t.cases, t.prefix_cases, t.subset_cases, t.torn_prefix_cases,
           t.torn_word_cases, t.nested_cases, t.as_old, t.as_new, t.mixed, t.bad_code, t.relive_fail);
    int ok = t.mixed == 0 && t.bad_code == 0 && t.relive_fail == 0 && t.as_old > 0 && t.as_new > 0;
    free(pre); free(img); free(img2); free(e.media);
    return ok;
}

/* ---------------- barrier lost ---------------- */

/* A device that acknowledges FLUSH without ordering (outside the protocol's
 * device contract). Body and header writes then form one epoch and may land
 * in any combination. The full-record digest must still keep recovery to
 * complete old or complete new. Every subset of all 2m blocks is enumerated,
 * plus a torn first header block over every body subset. */
static int barrier_lost(uint32_t bs, unsigned gens)
{
    unsigned m = TS_RECORD_BYTES / bs;
    uint64_t base = 0, nblocks = (uint64_t)TS_UNITS * m;
    size_t bytes = (size_t)nblocks * bs;
    emu e;
    emu_init(&e, bs, nblocks);
    uint8_t *pre = malloc(bytes), *img = malloc(bytes);
    uint8_t oldr[TS_RECORD_BYTES], newr[TS_RECORD_BYTES], got[TS_RECORD_BYTES];
    uint64_t seq;
    if (!pre || !img) abort();
    tally t;
    memset(&t, 0, sizeof t);
    ts_device d = emu_dev(&e);
    ts_region r;
    CHECK(ts_open(&r, &d, base) == TS_OK);
    CHECK(ts_recover(&r, got, &seq, NULL) == TS_EMPTY);
    memset(oldr, 0, sizeof oldr);
    for (unsigned g = 1; g <= gens; g++) {
        make_record(newr, g);
        memcpy(pre, e.media, bytes);
        e.tracing = 1;
        CHECK(ts_commit(&r, newr) == TS_OK);
        e.tracing = 0;
        for (unsigned i = 0; i < e.ntrace; i++) e.trace[i].epoch = 0; /* barrier lost */
        crash_spec c;
        memset(&c, 0, sizeof c);
        c.cut_epoch = 0;
        c.n = 2 * m;
        for (uint32_t mask = 0; mask < (1u << (2 * m)); mask++) {
            for (unsigned i = 0; i < 2 * m; i++) c.fate[i] = (mask >> i) & 1 ? FATE_NEW : FATE_OLD;
            build_crash(&e, pre, img, &c);
            classify(bs, nblocks, base, img, oldr, g - 1, newr, g, &t, 0, 0);
            t.subset_cases++;
        }
        for (uint32_t mask = 0; mask < (1u << m); mask++) {
            for (uint32_t b = 8; b < bs; b += 8) {
                for (unsigned i = 0; i < m; i++) c.fate[i] = (mask >> i) & 1 ? FATE_NEW : FATE_OLD;
                for (unsigned i = m; i < 2 * m; i++) c.fate[i] = FATE_OLD;
                c.fate[m] = FATE_TORN_PREFIX;
                c.torn_bytes = b;
                build_crash(&e, pre, img, &c);
                classify(bs, nblocks, base, img, oldr, g - 1, newr, g, &t, 0, 0);
                t.torn_prefix_cases++;
            }
        }
        emu_clear_trace(&e);
        memcpy(oldr, newr, sizeof oldr);
    }
    printf("  barrier lost bs=%u gens=%u: cases=%llu (subset=%llu torn_header=%llu) as_old=%llu as_new=%llu "
           "mixed=%llu error=%llu\n", bs, gens, t.cases, t.subset_cases, t.torn_prefix_cases, t.as_old,
           t.as_new, t.mixed, t.bad_code);
    free(pre); free(img); free(e.media);
    return t.mixed == 0 && t.bad_code == 0 && t.as_old > 0 && t.as_new > 0;
}

/* ---------------- negative control ---------------- */

/* A naive in-place write of the 4096-byte record, no slots, no digest, under
 * the same injector. The injector must find mixed records here, or it is not
 * testing anything. */
static unsigned long long naive_control(uint32_t bs)
{
    unsigned m = TS_RECORD_BYTES / bs;
    uint8_t oldr[TS_RECORD_BYTES], newr[TS_RECORD_BYTES], img[TS_RECORD_BYTES];
    make_record(oldr, 1);
    make_record(newr, 2);
    unsigned long long mixed = 0;
    for (unsigned mask = 0; mask < (1u << m); mask++) {
        for (unsigned i = 0; i < m; i++)
            memcpy(img + i * bs, ((mask >> i) & 1 ? newr : oldr) + i * bs, bs);
        if (memcmp(img, oldr, sizeof img) && memcmp(img, newr, sizeof img)) mixed++;
    }
    for (unsigned k = 0; k < m; k++)
        for (uint32_t b = 1; b < bs; b++) {
            memcpy(img, newr, (size_t)k * bs);
            memcpy(img + k * bs, oldr + k * bs, (size_t)(m - k) * bs);
            memcpy(img + k * bs, newr + k * bs, b);
            if (memcmp(img, oldr, sizeof img) && memcmp(img, newr, sizeof img)) mixed++;
        }
    return mixed;
}

/* ---------------- rule tests ---------------- */

static void rule_tests(void)
{
    emu e;
    ts_region r;
    ts_device d;
    uint8_t got[TS_RECORD_BYTES], a[TS_RECORD_BYTES], b[TS_RECORD_BYTES];
    uint64_t seq;
    ts_slot_state st[2];

    /* Geometry: only 512 and 4096; region must fit. */
    uint32_t bad_bs[] = {0, 520, 1024, 2048, 8192};
    for (unsigned i = 0; i < sizeof bad_bs / sizeof bad_bs[0]; i++) {
        emu_init(&e, 512, 64);
        d = emu_dev(&e);
        d.block_size = bad_bs[i];
        CHECK(ts_open(&r, &d, 0) == TS_EGEOMETRY);
        free(e.media);
    }
    emu_init(&e, 512, 31); d = emu_dev(&e); CHECK(ts_open(&r, &d, 0) == TS_EGEOMETRY); free(e.media);
    emu_init(&e, 512, 32); d = emu_dev(&e); CHECK(ts_open(&r, &d, 0) == TS_OK);
    CHECK(ts_open(&r, &d, 1) == TS_EGEOMETRY); free(e.media);
    emu_init(&e, 4096, 4); d = emu_dev(&e); CHECK(ts_open(&r, &d, 0) == TS_OK); free(e.media);

    /* Commit before recover is refused. */
    emu_init(&e, 512, 32); d = emu_dev(&e);
    CHECK(ts_open(&r, &d, 0) == TS_OK);
    make_record(a, 1);
    CHECK(ts_commit(&r, a) == TS_ESTATE);
    CHECK(e.writes == 0);

    /* Blank recovers EMPTY with both slots blank. */
    CHECK(ts_recover(&r, got, &seq, st) == TS_EMPTY);
    CHECK(st[0] == TS_SLOT_BLANK && st[1] == TS_SLOT_BLANK);
    CHECK(ts_commit(&r, a) == TS_OK);
    CHECK(e.flushes == 2);
    make_record(b, 2);
    CHECK(ts_commit(&r, b) == TS_OK);
    CHECK(ts_recover(&r, got, &seq, st) == TS_OK && seq == 2 && !memcmp(got, b, sizeof b));
    CHECK(st[0] == TS_SLOT_VALID && st[1] == TS_SLOT_VALID);

    /* Media damage in the newest body: falls back to the older complete record. */
    uint8_t *body_b = e.media + 2 * TS_RECORD_BYTES;
    body_b[1234] ^= 1;
    CHECK(ts_recover(&r, got, &seq, st) == TS_OK && seq == 1 && !memcmp(got, a, sizeof a));
    CHECK(st[1] == TS_SLOT_INVALID);
    /* The next commit overwrites the damaged slot, never the good one. */
    make_record(b, 5);
    CHECK(ts_commit(&r, b) == TS_OK);
    CHECK(ts_recover(&r, got, &seq, st) == TS_OK && seq == 2 && !memcmp(got, b, sizeof b));

    /* Non-zero byte in the commit unit tail invalidates the slot. */
    e.media[3 * TS_RECORD_BYTES + 100] = 1;
    CHECK(ts_recover(&r, got, &seq, st) == TS_OK && seq == 1 && st[1] == TS_SLOT_INVALID);
    e.media[3 * TS_RECORD_BYTES + 100] = 0;

    /* A header whose own digest does not verify is rejected. */
    e.media[3 * TS_RECORD_BYTES + 60] ^= 1;
    CHECK(ts_recover(&r, got, &seq, st) == TS_OK && seq == 1 && st[1] == TS_SLOT_INVALID);
    e.media[3 * TS_RECORD_BYTES + 60] ^= 1;

    /* Both commit units damaged: CORRUPT, and commit is refused. */
    e.media[1 * TS_RECORD_BYTES + 20] ^= 1;
    e.media[3 * TS_RECORD_BYTES + 20] ^= 1;
    CHECK(ts_recover(&r, got, &seq, st) == TS_CORRUPT);
    unsigned long w = e.writes;
    CHECK(ts_commit(&r, a) == TS_ESTATE && e.writes == w);
    e.media[1 * TS_RECORD_BYTES + 20] ^= 1;
    e.media[3 * TS_RECORD_BYTES + 20] ^= 1;

    /* Slot A blank but slot B non-blank and invalid: a crash cannot do that. */
    memset(e.media + 1 * TS_RECORD_BYTES, 0, TS_RECORD_BYTES);
    e.media[3 * TS_RECORD_BYTES + 20] ^= 1;
    CHECK(ts_recover(&r, got, &seq, st) == TS_CORRUPT);
    e.media[3 * TS_RECORD_BYTES + 20] ^= 1;

    /* Equal seq in two valid slots: CONFLICT. */
    ts_encode_commit(e.media + 1 * TS_RECORD_BYTES, 0, 7, e.media);
    ts_encode_commit(e.media + 3 * TS_RECORD_BYTES, 1, 7, e.media + 2 * TS_RECORD_BYTES);
    CHECK(ts_recover(&r, got, &seq, st) == TS_CONFLICT);

    /* A header copied into the other slot fails the slot id check. */
    ts_encode_commit(e.media + 1 * TS_RECORD_BYTES, 0, 8, e.media);
    memcpy(e.media + 3 * TS_RECORD_BYTES, e.media + 1 * TS_RECORD_BYTES, TS_RECORD_BYTES);
    memcpy(e.media + 2 * TS_RECORD_BYTES, e.media, TS_RECORD_BYTES);
    CHECK(ts_recover(&r, got, &seq, st) == TS_OK && seq == 8 && st[1] == TS_SLOT_INVALID);

    /* Read error is EIO, never a verdict about the media. */
    e.fail_read_at = (int)e.reads;
    CHECK(ts_recover(&r, got, &seq, st) == TS_EIO);
    CHECK(ts_commit(&r, a) == TS_ESTATE);
    e.fail_read_at = -1;
    free(e.media);

    /* Sequence exhaustion is refused, not wrapped. */
    emu_init(&e, 4096, 4); d = emu_dev(&e);
    CHECK(ts_open(&r, &d, 0) == TS_OK);
    ts_encode_commit(e.media + TS_RECORD_BYTES, 0, UINT64_MAX, e.media);
    CHECK(ts_recover(&r, got, &seq, st) == TS_OK && seq == UINT64_MAX);
    CHECK(ts_commit(&r, a) == TS_ESTATE);
    free(e.media);
}

int main(void)
{
    xs_state = 0x243F6A8885A308D3ull;
    int all_ok = 1;

    rule_tests();
    unsigned long long rule_fail = failures;
    printf("TORN_SLOT_RULES: %s (%llu checks)\n", rule_fail ? "FAIL" : "PASS", checks);
    all_ok &= rule_fail == 0;

    unsigned long long n512 = naive_control(512), n4096 = naive_control(4096);
    printf("NAIVE_IN_PLACE_CONTROL: mixed records found bs=512: %llu, bs=4096: %llu (expected > 0)\n",
           n512, n4096);
    int ctl = n512 > 0 && n4096 > 0;
    printf("TORN_INJECTOR_DETECTS_MIXES: %s\n", ctl ? "PASS" : "FAIL");
    all_ok &= ctl;

    struct { uint32_t bs; uint64_t base; } geo[] = {{512, 0}, {512, 3}, {512, 8}, {4096, 0}, {4096, 1}};
    int ok512 = 1, ok4096 = 1;
    for (unsigned i = 0; i < sizeof geo / sizeof geo[0]; i++) {
        int ok = campaign(geo[i].bs, geo[i].base, 6, 1);
        if (geo[i].bs == 512) ok512 &= ok; else ok4096 &= ok;
    }
    printf("TORN_SLOT_FAULT_INJECTION_512: %s\n", ok512 ? "PASS" : "FAIL");
    printf("TORN_SLOT_FAULT_INJECTION_4096: %s\n", ok4096 ? "PASS" : "FAIL");
    all_ok &= ok512 && ok4096;

    int bl = barrier_lost(512, 3) & barrier_lost(4096, 6);
    printf("TORN_SLOT_BARRIER_LOST_512_4096: %s (device ignores FLUSH ordering; outside the device contract)\n",
           bl ? "PASS" : "FAIL");
    all_ok &= bl;

    printf("checks=%llu failures=%llu\n", checks, failures);
    printf("TORN_SLOT_HOST_EMULATION: %s (host block-device emulation, not QEMU, not hardware)\n",
           all_ok && failures == 0 ? "PASS" : "FAIL");
    return all_ok && failures == 0 ? 0 : 1;
}
