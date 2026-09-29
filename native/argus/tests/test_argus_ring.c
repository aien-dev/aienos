/*
 * test_argus_ring.c -- ARGUS lane B: SPSC ring tests.
 *   init/argument errors, watermark (saturation) points per class, drop
 *   reporting, and a two-thread run with a deliberately slow consumer:
 *   attempts == popped + sum(refused) + critical_overflow, FIFO per class,
 *   and every refusal reported exactly once by argus_ring_drain_drops.
 * Usage: test_argus_ring [events] [--allow-no-refusals]   (default 10,000,000)
 * --allow-no-refusals: for sanitizer builds, where the slowed producer may
 * never outrun the consumer; the identity and FIFO checks still apply.
 */
#include "argus_abi.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The ring enforces only the class floor of argus_event_min_class(kind). No v1 kind
 * may be INFORMATIONAL, so the INFORMATIONAL watermark is exercised with a kind
 * value that is not in v1 (no floor at the ring; the core would reject it). */
#define NOFLOOR_KIND 0x7FFFu
static uint16_t kind_for(uint8_t cls)
{
    return cls == 1 ? ARGUS_EV_FORGED_CAPABILITY : cls == 2 ? ARGUS_EV_CAPABILITY_DENIED
         : cls == 3 ? ARGUS_EV_CAPABILITY_USED : NOFLOOR_KIND;
}

static int failures;
#define CHECK(cond) do { if (!(cond)) { failures++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

static ArgusEvent mk(uint8_t cls, uint64_t seq, uint64_t resource)
{
    ArgusEvent e;
    memset(&e, 0, sizeof e);
    e.version = ARGUS_ABI_VERSION;
    e.class_ = cls;
    e.kind = kind_for(cls);
    e.outcome = ARGUS_OUTCOME_OK;
    e.flags = ARGUS_FLAG_SYNTHETIC;
    e.sequence = seq;
    e.resource = resource;
    return e;
}

static ArgusRing *new_ring(uint32_t cap, void **mem_out)
{
    size_t fp = argus_ring_footprint(cap);
    void *mem = NULL;
    if (fp == 0 || posix_memalign(&mem, 64, fp) != 0) { fprintf(stderr, "alloc failed\n"); exit(2); }
    ArgusRing *r = NULL;
    if (argus_ring_init(&r, mem, fp, cap) != ARGUS_OK) { fprintf(stderr, "init failed\n"); exit(2); }
    *mem_out = mem;
    return r;
}

static void test_init(void)
{
    CHECK(argus_ring_footprint(0) == 0);
    CHECK(argus_ring_footprint(2) == 0);
    CHECK(argus_ring_footprint(12) == 0);
    CHECK(argus_ring_footprint(4) >= 4 * sizeof(ArgusEvent));
    CHECK(argus_ring_footprint(1024) - argus_ring_footprint(512) == 512 * sizeof(ArgusEvent));
    size_t fp = argus_ring_footprint(16);
    void *mem = NULL;
    CHECK(posix_memalign(&mem, 64, fp + 64) == 0);
    ArgusRing *r = NULL;
    CHECK(argus_ring_init(NULL, mem, fp, 16) == ARGUS_ERR_ARG);
    CHECK(argus_ring_init(&r, NULL, fp, 16) == ARGUS_ERR_ARG);
    CHECK(argus_ring_init(&r, mem, fp - 1, 16) == ARGUS_ERR_ARG);
    CHECK(argus_ring_init(&r, mem, fp, 15) == ARGUS_ERR_ARG);
    CHECK(argus_ring_init(&r, (char *)mem + 8, fp, 16) == ARGUS_ERR_ARG);
    CHECK(argus_ring_init(&r, mem, fp, 16) == ARGUS_OK);
    ArgusEvent e = mk(ARGUS_CLASS_AUDIT, 1, 0), o;
    CHECK(argus_ring_pop(r, &o) == ARGUS_ERR_STATE);
    CHECK(argus_ring_pop_batch(r, &o, 1) == 0);
    CHECK(argus_ring_push(NULL, &e) == ARGUS_ERR_ARG);
    CHECK(argus_ring_push(r, NULL) == ARGUS_ERR_ARG);
    e.class_ = 0; CHECK(argus_ring_push(r, &e) == ARGUS_ERR_MALFORMED);
    e.class_ = 5; CHECK(argus_ring_push(r, &e) == ARGUS_ERR_MALFORMED);
    e.class_ = ARGUS_CLASS_AUDIT;
    CHECK(argus_ring_push(r, &e) == ARGUS_OK);
    CHECK(argus_ring_pop(r, &o) == ARGUS_OK && memcmp(&o, &e, sizeof o) == 0);
    ArgusRingStats s;
    argus_ring_stats(r, &s);
    CHECK(s.pushed == 1 && s.popped == 1 && s.depth == 0 && s.capacity == 16);
    CHECK(s.refused[0] == 2 && s.refused[1] == 0 && s.refused[2] == 0 && s.refused[3] == 0 && s.refused[4] == 0);
    free(mem);
    printf("init/args: OK\n");
}

/* Class weaker than the kind floor: MALFORMED, stored nowhere, counted in refused[0]
 * only (not a drop, never drained). Every kind value x every class byte. */
static void test_class_floor(void)
{
    void *mem; ArgusRing *r = new_ring(1024, &mem);
    uint64_t attempts = 0, ok = 0, bad = 0;
    for (unsigned k = 0; k < 65536; k++) {
        unsigned fl = argus_event_min_class((uint16_t)k);
        for (unsigned c = 0; c < 256; c++) {
            ArgusEvent e = mk((uint8_t)c, 1, 0), o;
            e.kind = (uint16_t)k;
            int want = (c >= 1 && c <= 4 && (fl == 0 || c <= fl) && k != 90) ? ARGUS_OK : ARGUS_ERR_MALFORMED;   /* v1.2: 90 refused */
            int rc = argus_ring_push(r, &e);
            CHECK(rc == want);
            attempts++;
            if (rc == ARGUS_OK) { ok++; CHECK(argus_ring_pop(r, &o) == ARGUS_OK); } else bad++;
        }
    }
    ArgusRingStats s;
    argus_ring_stats(r, &s);
    CHECK(s.refused[0] == bad && s.pushed == ok && s.popped == ok);
    CHECK(s.refused[1] + s.refused[2] + s.refused[3] + s.refused[4] == 0 && s.critical_overflow == 0);
    CHECK(attempts == s.pushed + s.refused[0]);
    ArgusEvent d[8]; uint64_t seq = 1;
    CHECK(argus_ring_drain_drops(r, d, 8, &seq) == 0);   /* malformed is not telemetry loss */
    /* The hostile cases by name. */
    ArgusEvent e = mk(ARGUS_CLASS_INFORMATIONAL, 1, 0); e.kind = ARGUS_EV_CAPABILITY_REVOKED;
    CHECK(argus_ring_push(r, &e) == ARGUS_ERR_MALFORMED);
    e.class_ = ARGUS_CLASS_SECURITY; CHECK(argus_ring_push(r, &e) == ARGUS_ERR_MALFORMED);
    e.class_ = ARGUS_CLASS_CRITICAL; CHECK(argus_ring_push(r, &e) == ARGUS_OK);
    e.kind = ARGUS_EV_PROVIDER_USED; e.class_ = ARGUS_CLASS_INFORMATIONAL; CHECK(argus_ring_push(r, &e) == ARGUS_ERR_MALFORMED);
    e.class_ = ARGUS_CLASS_AUDIT; CHECK(argus_ring_push(r, &e) == ARGUS_OK);
    /* v1.2 (ARGUS1_SPEC 3): kind 90 is refused at every class, CONSUMER flag or not; 91-93 are
     * CRITICAL-floor transport. None of this is telemetry loss. */
    {
        ArgusRingStats s0, s1; argus_ring_stats(r, &s0);
        ArgusEvent p = mk(ARGUS_CLASS_CRITICAL, 1, 0), o;
        while (argus_ring_pop(r, &o) == ARGUS_OK) { }   /* the named cases above left events queued */ p.kind = ARGUS_EV_CONTAINMENT_PROPOSED;
        CHECK(argus_ring_push(r, &p) == ARGUS_ERR_MALFORMED);
        p.flags = ARGUS_FLAG_CONSUMER; CHECK(argus_ring_push(r, &p) == ARGUS_ERR_MALFORMED);
        argus_ring_stats(r, &s1);
        CHECK(s1.refused[0] == s0.refused[0] + 2 && s1.pushed == s0.pushed);
        for (uint16_t k = ARGUS_EV_CONTAINMENT_DECIDED; k <= ARGUS_EV_AUTHORITY_ESCALATED; k++) {
            ArgusEvent q = mk(ARGUS_CLASS_CRITICAL, 1, 0); q.kind = k;
            CHECK(argus_ring_push(r, &q) == ARGUS_OK && argus_ring_pop(r, &o) == ARGUS_OK && o.kind == k);
            q.class_ = ARGUS_CLASS_SECURITY; CHECK(argus_ring_push(r, &q) == ARGUS_ERR_MALFORMED);
        }
        CHECK(argus_ring_drain_drops(r, d, 8, &seq) == 0);
    }
    {   /* a full ring never drops 91-93 silently: sticky critical_overflow */
        void *m2; ArgusRing *r2 = new_ring(16, &m2);
        ArgusEvent q = mk(ARGUS_CLASS_CRITICAL, 1, 0); q.kind = ARGUS_EV_CONTAINMENT_EXECUTED;
        int rc = ARGUS_OK; unsigned pushed = 0;
        while ((rc = argus_ring_push(r2, &q)) == ARGUS_OK && pushed < 64) pushed++;
        ArgusRingStats s2; argus_ring_stats(r2, &s2);
        CHECK(rc == ARGUS_ERR_FULL && s2.critical_overflow == 1 && s2.refused[0] == 0);
        free(m2);
    }
    free(mem);
    printf("class floor: %llu pushes (every kind x every class byte), %llu MALFORMED counted in refused[0], "
           "none drained\n", (unsigned long long)attempts, (unsigned long long)bad);
}

/* For each capacity and class: the depth at which the class is first refused,
 * measured both alone and on top of CRITICAL fill, equals the saturation point. */
static void test_watermarks(void)
{
    static const uint32_t caps[] = { 4, 8, 16, 64, 1024 };
    static const char *names[] = { "", "CRITICAL", "SECURITY", "AUDIT", "INFORMATIONAL" };
    for (size_t ci = 0; ci < sizeof caps / sizeof caps[0]; ci++) {
        uint32_t cap = caps[ci];
        for (uint8_t cls = 1; cls <= ARGUS_CLASS_MAX; cls++) {
            uint32_t sat = argus_ring_saturation_point(cap, cls);
            /* ceil(cap * {100,90,75,50}%) written in twentieths */
            uint64_t expect = ((uint64_t)cap * (cls == 1 ? 20 : cls == 2 ? 18 : cls == 3 ? 15 : 10) + 19) / 20;
            CHECK(sat == expect);
            /* alone */
            void *mem; ArgusRing *r = new_ring(cap, &mem);
            uint32_t depth = 0;
            while (argus_ring_push(r, &(ArgusEvent){ .version = 1, .class_ = cls, .kind = NOFLOOR_KIND, .outcome = 1, .sequence = 1 }) == ARGUS_OK)
                depth++;
            CHECK(depth == sat);
            free(mem);
            /* on top of d CRITICAL events */
            for (uint32_t d = 0; d <= cap; d++) {
                r = new_ring(cap, &mem);
                for (uint32_t k = 0; k < d; k++) CHECK(argus_ring_push(r, &(ArgusEvent){ .version = 1, .class_ = 1, .kind = NOFLOOR_KIND, .outcome = 1, .sequence = 1 }) == (k < cap ? ARGUS_OK : ARGUS_ERR_FULL));
                int rc = argus_ring_push(r, &(ArgusEvent){ .version = 1, .class_ = cls, .kind = NOFLOOR_KIND, .outcome = 1, .sequence = 1 });
                CHECK(rc == (d < sat ? ARGUS_OK : ARGUS_ERR_FULL));
                free(mem);
            }
            if (cap == 1024) printf("  cap 1024 %-13s refused from depth %4u (%.1f%%)\n", names[cls], sat, 100.0 * sat / cap);
        }
    }
    printf("watermarks: OK for capacities 4, 8, 16, 64, 1024\n");
}

static void test_drain_drops(void)
{
    void *mem; ArgusRing *r = new_ring(8, &mem);
    ArgusRingStats s;
    ArgusEvent out[8];
    uint64_t seq = 0;
    CHECK(argus_ring_drain_drops(r, out, 8, &seq) == 0);
    /* Fill to 4 with SECURITY: INFO refused (limit 4). */
    for (int i = 0; i < 4; i++) CHECK(argus_ring_push(r, &(ArgusEvent){ .version = 1, .class_ = 2, .kind = NOFLOOR_KIND, .outcome = 1, .sequence = 1 }) == ARGUS_OK);
    for (int i = 0; i < 3; i++) CHECK(argus_ring_push(r, &(ArgusEvent){ .version = 1, .class_ = 4, .kind = NOFLOOR_KIND, .outcome = 1, .sequence = 1 }) == ARGUS_ERR_FULL);
    for (int i = 0; i < 2; i++) CHECK(argus_ring_push(r, &(ArgusEvent){ .version = 1, .class_ = 2, .kind = NOFLOOR_KIND, .outcome = 1, .sequence = 1 }) == ARGUS_OK);
    /* depth 6 = AUDIT limit (6) */
    CHECK(argus_ring_push(r, &(ArgusEvent){ .version = 1, .class_ = 3, .kind = NOFLOOR_KIND, .outcome = 1, .sequence = 1 }) == ARGUS_ERR_FULL);
    argus_ring_stats(r, &s);
    CHECK(s.refused[4] == 3 && s.refused[3] == 1 && s.refused[2] == 0 && s.critical_overflow == 0 && s.depth == 6);

    CHECK(argus_ring_drain_drops(r, out, 8, NULL) == 0);
    CHECK(argus_ring_drain_drops(r, out, 1, &seq) == 1);   /* max honoured: AUDIT first (higher class), INFO stays pending */
    CHECK(seq == 2 && out[0].sequence == 1);
    CHECK(out[0].kind == ARGUS_EV_TELEMETRY_DROPPED && out[0].class_ == ARGUS_CLASS_CRITICAL);   /* floor of TELEMETRY_DROPPED */
    CHECK(out[0].flags == ARGUS_FLAG_CONSUMER && out[0].object_id == ARGUS_CLASS_AUDIT && out[0].resource == 1 && out[0].cap_id == ARGUS_CAP_NONE);
    CHECK(argus_event_validate(&out[0]) == ARGUS_OK);
    CHECK(argus_ring_drain_drops(r, out, 8, &seq) == 1);
    CHECK(out[0].object_id == ARGUS_CLASS_INFORMATIONAL && out[0].resource == 3 && out[0].sequence == 2);
    CHECK(argus_ring_drain_drops(r, out, 8, &seq) == 0);   /* reset after report */
    argus_ring_stats(r, &s);
    CHECK(s.refused[4] == 3 && s.refused[3] == 1);          /* cumulative stats unchanged */

    /* Fill to full with CRITICAL, overflow twice. */
    CHECK(argus_ring_push(r, &(ArgusEvent){ .version = 1, .class_ = 1, .kind = NOFLOOR_KIND, .outcome = 1, .sequence = 1 }) == ARGUS_OK);
    CHECK(argus_ring_push(r, &(ArgusEvent){ .version = 1, .class_ = 1, .kind = NOFLOOR_KIND, .outcome = 1, .sequence = 1 }) == ARGUS_OK);
    CHECK(argus_ring_push(r, &(ArgusEvent){ .version = 1, .class_ = 1, .kind = NOFLOOR_KIND, .outcome = 1, .sequence = 1 }) == ARGUS_ERR_FULL);
    CHECK(argus_ring_push(r, &(ArgusEvent){ .version = 1, .class_ = 1, .kind = NOFLOOR_KIND, .outcome = 1, .sequence = 1 }) == ARGUS_ERR_FULL);
    CHECK(argus_ring_push(r, &(ArgusEvent){ .version = 1, .class_ = 2, .kind = NOFLOOR_KIND, .outcome = 1, .sequence = 1 }) == ARGUS_ERR_FULL);
    argus_ring_stats(r, &s);
    CHECK(s.critical_overflow == 2 && s.refused[1] == 0 && s.refused[2] == 1 && s.depth == 8);
    CHECK(argus_ring_drain_drops(r, out, 8, &seq) == 2);
    CHECK(out[0].object_id == ARGUS_CLASS_CRITICAL && out[0].resource == 2 && out[0].class_ == ARGUS_CLASS_CRITICAL);
    CHECK(out[1].object_id == ARGUS_CLASS_SECURITY && out[1].resource == 1 && out[1].class_ == ARGUS_CLASS_CRITICAL);
    /* Drop reports are always CRITICAL class; stats keep the overflow (sticky). */
    CHECK(argus_ring_push(r, &(ArgusEvent){ .version = 1, .class_ = 4, .kind = NOFLOOR_KIND, .outcome = 1, .sequence = 1 }) == ARGUS_ERR_FULL);
    CHECK(argus_ring_drain_drops(r, out, 8, &seq) == 1);
    CHECK(out[0].class_ == ARGUS_CLASS_CRITICAL && out[0].object_id == ARGUS_CLASS_INFORMATIONAL);
    argus_ring_stats(r, &s);
    CHECK(s.critical_overflow == 2);
    free(mem);
    printf("drain_drops: OK (max honoured, reset after report, always CRITICAL, sticky critical overflow)\n");
}

/* ---- two-thread SPSC run ---- */
#define SPSC_CAP 1024u
typedef struct {
    ArgusRing *r;
    uint64_t events;
    _Atomic int producer_done;
    /* producer results */
    uint64_t attempts, accepted[5], refused_rc[5];
    /* consumer results */
    uint64_t popped, fifo_errors, content_errors, reported[5], drop_events, last_seq;
} Spsc;

static uint64_t xs(uint64_t *s) { uint64_t x = *s; x ^= x << 13; x ^= x >> 7; x ^= x << 17; return *s = x; }

static void *producer(void *arg)
{
    Spsc *t = arg;
    uint64_t rs = 0x1234567887654321ull, next[5] = {0};
    for (uint64_t i = 0; i < t->events; i++) {
        uint64_t roll = xs(&rs) % 100;
        uint8_t cls = roll < 5 ? 1 : roll < 30 ? 2 : roll < 60 ? 3 : 4;
        ArgusEvent e = mk(cls, i + 1, ++next[cls]);   /* resource = per-class attempt number */
        e.object_id = (uint32_t)(i * 2654435761u);
        int rc = argus_ring_push(t->r, &e);
        t->attempts++;
        if (rc == ARGUS_OK) t->accepted[cls]++;
        else if (rc == ARGUS_ERR_FULL) t->refused_rc[cls]++;
        else { fprintf(stderr, "FAIL push rc %d\n", rc); exit(1); }
    }
    atomic_store_explicit(&t->producer_done, 1, memory_order_release);
    return NULL;
}

static void consume_drops(Spsc *t, uint64_t *drop_seq)
{
    ArgusEvent d[4];
    size_t n = argus_ring_drain_drops(t->r, d, 4, drop_seq);
    for (size_t i = 0; i < n; i++) {
        if (d[i].kind != ARGUS_EV_TELEMETRY_DROPPED || d[i].object_id < 1 || d[i].object_id > 4 ||
            argus_event_validate(&d[i]) != ARGUS_OK)
            t->content_errors++;
        else
            t->reported[d[i].object_id] += d[i].resource;
        t->drop_events++;
    }
}

static void *consumer(void *arg)
{
    Spsc *t = arg;
    uint64_t last_res[5] = {0}, last_seq = 0, drop_seq = 1;
    volatile uint64_t sink = 0;
    for (;;) {
        ArgusEvent e;
        int done = atomic_load_explicit(&t->producer_done, memory_order_acquire);
        if (argus_ring_pop(t->r, &e) == ARGUS_OK) {
            t->popped++;
            uint8_t c = e.class_;
            if (c < 1 || c > 4 || e.object_id != (uint32_t)((e.sequence - 1) * 2654435761u)) t->content_errors++;
            else {
                if (e.resource <= last_res[c]) t->fifo_errors++;
                last_res[c] = e.resource;
                if (e.sequence <= last_seq) t->fifo_errors++;
                last_seq = e.sequence;
            }
            for (int k = 0; k < 40; k++) sink += (uint64_t)k * e.sequence;   /* slow consumer */
            if ((t->popped & 1023) == 0) consume_drops(t, &drop_seq);
        } else if (done) {
            break;   /* done was read before the failed pop: ring is truly drained */
        }
    }
    consume_drops(t, &drop_seq);
    consume_drops(t, &drop_seq);
    t->last_seq = last_seq;
    (void)sink;
    return NULL;
}

static void test_spsc(uint64_t events, int require_refusals)
{
    Spsc t;
    memset(&t, 0, sizeof t);
    void *mem;
    t.r = new_ring(SPSC_CAP, &mem);
    t.events = events;
    atomic_init(&t.producer_done, 0);
    pthread_t pc, cc;
    pthread_create(&cc, NULL, consumer, &t);
    pthread_create(&pc, NULL, producer, &t);
    pthread_join(pc, NULL);
    pthread_join(cc, NULL);

    ArgusRingStats s;
    argus_ring_stats(t.r, &s);
    uint64_t sum_refused = s.refused[1] + s.refused[2] + s.refused[3] + s.refused[4];
    uint64_t accepted = t.accepted[1] + t.accepted[2] + t.accepted[3] + t.accepted[4];
    printf("spsc: %llu attempts, %llu popped, refused SEC %llu AUDIT %llu INFO %llu, critical_overflow %llu, "
           "%llu drop events\n",
           (unsigned long long)t.attempts, (unsigned long long)t.popped, (unsigned long long)s.refused[2],
           (unsigned long long)s.refused[3], (unsigned long long)s.refused[4],
           (unsigned long long)s.critical_overflow, (unsigned long long)t.drop_events);
    printf("  accepted per class CRIT %llu SEC %llu AUDIT %llu INFO %llu\n",
           (unsigned long long)t.accepted[1], (unsigned long long)t.accepted[2],
           (unsigned long long)t.accepted[3], (unsigned long long)t.accepted[4]);
    CHECK(t.attempts == events);
    CHECK(t.attempts == t.popped + sum_refused + s.critical_overflow);   /* the transport identity */
    CHECK(s.pushed == accepted && s.popped == t.popped && s.depth == 0);
    CHECK(s.refused[1] == 0);
    CHECK(s.critical_overflow == t.refused_rc[1]);
    for (int c = 2; c <= 4; c++) CHECK(s.refused[c] == t.refused_rc[c]);
    for (int c = 1; c <= 4; c++) CHECK(t.reported[c] == t.refused_rc[c]);   /* every refusal reported exactly once */
    CHECK(t.fifo_errors == 0);
    CHECK(t.content_errors == 0);
    if (require_refusals) CHECK(sum_refused > 0);   /* the consumer really was slow */
    else if (sum_refused == 0) printf("  note: consumer kept up in this run; refusal path not exercised\n");
    free(mem);
    printf("spsc: identity attempts == popped + sum(refused) + critical_overflow holds; FIFO per class OK; "
           "all refusals reported by drain_drops\n");
}

int main(int argc, char **argv)
{
    uint64_t events = argc > 1 ? strtoull(argv[1], NULL, 10) : 10000000ull;
    test_init();
    test_class_floor();
    test_watermarks();
    test_drain_drops();
    int require_refusals = !(argc > 2 && strcmp(argv[2], "--allow-no-refusals") == 0);
    test_spsc(events, require_refusals);
    if (failures) { printf("test_argus_ring: FAIL (%d)\n", failures); return 1; }
    printf("test_argus_ring: PASS\n");
    return 0;
}
