/*
 * bench_argus_ring.c -- ARGUS lane B: ring saturation benchmark.
 * Prints: bytes per event, ring footprint, the depth at which each class
 * starts being refused (argus_ring_saturation_point, confirmed empirically),
 * push latency p50/p99 (uncontended and with a live consumer), and pops/s.
 * Timing (test code only; the ring itself makes no system calls):
 * clock_gettime_nsec_np(CLOCK_UPTIME_RAW) on macOS, CLOCK_MONOTONIC_RAW
 * elsewhere. Timer granularity (tens of ns on Apple silicon) is too coarse
 * for one push, so each latency sample is one batch of BATCH pushes timed
 * together and divided by BATCH; p50/p99 are over those batch samples. The
 * timer pair cost is printed and already amortised over the batch.
 */
#include "argus_abi.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


#define CAP 4096u
#define SAMPLES 200000u
#define BATCH 32u

static uint64_t now_ns(void)
{
#ifdef __APPLE__
    return clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#endif
}

static int cmp_dbl(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static int cmp_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

static ArgusRing *new_ring(uint32_t cap, void **mem)
{
    size_t fp = argus_ring_footprint(cap);
    ArgusRing *r = NULL;
    if (posix_memalign(mem, 64, fp) != 0 || argus_ring_init(&r, *mem, fp, cap) != ARGUS_OK) {
        fprintf(stderr, "ring init failed\n");
        exit(2);
    }
    return r;
}

/* A kind whose class floor admits cls (0x7FFF: no v1 kind, so no floor at the ring;
 * no v1 kind may be INFORMATIONAL, the watermark is kept for future kinds). */
static uint16_t kind_for(uint8_t cls)
{
    return cls == 1 ? ARGUS_EV_FORGED_CAPABILITY : cls == 2 ? ARGUS_EV_CAPABILITY_DENIED
         : cls == 3 ? ARGUS_EV_CAPABILITY_USED : 0x7FFF;
}

static ArgusEvent ev(uint8_t cls, uint64_t seq)
{
    ArgusEvent e;
    memset(&e, 0, sizeof e);
    e.version = 1; e.class_ = cls; e.kind = kind_for(cls); e.outcome = 1; e.sequence = seq;
    return e;
}

static void report(const char *name, double *s, size_t n)
{
    qsort(s, n, sizeof *s, cmp_dbl);
    printf("  %-40s p50 %6.2f ns  p99 %6.2f ns  p99.9 %7.2f ns  (per push, %u-push batches)\n",
           name, s[n / 2], s[(n * 99) / 100], s[(n * 999) / 1000], BATCH);
}

typedef struct { ArgusRing *r; _Atomic int stop; _Atomic uint64_t popped; } Cons;

static void *consumer(void *arg)
{
    Cons *c = arg;
    ArgusEvent buf[64];
    for (;;) {
        size_t n = argus_ring_pop_batch(c->r, buf, 64);
        atomic_fetch_add_explicit(&c->popped, n, memory_order_relaxed);
        if (n == 0 && atomic_load_explicit(&c->stop, memory_order_acquire)) {
            atomic_fetch_add_explicit(&c->popped, argus_ring_pop_batch(c->r, buf, 64), memory_order_relaxed);
            if (argus_ring_pop_batch(c->r, buf, 1) == 0) break;
            atomic_fetch_add_explicit(&c->popped, 1, memory_order_relaxed);
        }
    }
    return NULL;
}

int main(void)
{
    static const char *names[] = { "", "CRITICAL", "SECURITY", "AUDIT", "INFORMATIONAL" };
    uint32_t *t = malloc(SAMPLES * sizeof *t);
    double *s = malloc(SAMPLES * sizeof *s);
    if (!s || !t) return 2;
    void *mem;

    printf("bench_argus_ring (provisional; host-dependent)\n");
    printf("  bytes per event %u (sizeof ArgusEvent %zu)\n", ARGUS_EVENT_SIZE, sizeof(ArgusEvent));
    printf("  ring footprint: cap 1024 = %zu B, cap %u = %zu B, cap 65536 = %zu B (header %zu B)\n",
           argus_ring_footprint(1024), CAP, argus_ring_footprint(CAP), argus_ring_footprint(65536),
           argus_ring_footprint(1024) - 1024 * sizeof(ArgusEvent));

    /* Saturation points: formula vs measured (fill one class alone until refused). */
    printf("  saturation (cap %u): depth at which each class is first refused\n", CAP);
    for (uint8_t cls = 1; cls <= 4; cls++) {
        ArgusRing *r = new_ring(CAP, &mem);
        uint32_t d = 0;
        ArgusEvent e = ev(cls, 1);
        while (argus_ring_push(r, &e) == ARGUS_OK) d++;
        uint32_t sat = argus_ring_saturation_point(CAP, cls);
        printf("    %-13s point %5u (%5.1f%% fill), measured %5u %s\n", names[cls], sat, 100.0 * sat / CAP, d,
               d == sat ? "match" : "MISMATCH");
        free(mem);
        if (d != sat) return 1;
    }

    /* Timer cost. */
    for (uint32_t i = 0; i < SAMPLES; i++) { uint64_t a = now_ns(); t[i] = (uint32_t)(now_ns() - a); }
    qsort(t, SAMPLES, sizeof *t, cmp_u32);
    printf("  timer pair cost p50 %u ns (amortised over %u pushes per sample)\n", t[SAMPLES / 2], BATCH);

    /* Uncontended push: single thread, push a half ring then pop it back. */
    {
        ArgusRing *r = new_ring(CAP, &mem);
        static ArgusEvent buf[CAP / 2];
        uint64_t seq = 1;
        for (uint32_t k = 0; k < SAMPLES; k++) {
            ArgusEvent e[BATCH];
            for (uint32_t j = 0; j < BATCH; j++) e[j] = ev(ARGUS_CLASS_SECURITY, seq++);
            int bad = 0;
            uint64_t a = now_ns();
            for (uint32_t j = 0; j < BATCH; j++) bad |= argus_ring_push(r, &e[j]);
            s[k] = (double)(now_ns() - a) / BATCH;
            if (bad) { fprintf(stderr, "unexpected refusal\n"); return 1; }
            if ((k % ((CAP / 2) / BATCH)) == ((CAP / 2) / BATCH) - 1) argus_ring_pop_batch(r, buf, CAP / 2);
        }
        report("push, single thread (SECURITY)", s, SAMPLES);
        /* Bulk: no timer per push. */
        uint64_t n = 20000000ull, t0 = now_ns();
        for (uint64_t seq = 1; seq <= n; seq++) {
            ArgusEvent e = ev(ARGUS_CLASS_SECURITY, seq);
            argus_ring_push(r, &e);
            if ((seq % (CAP / 2)) == 0) argus_ring_pop_batch(r, buf, CAP / 2);
        }
        uint64_t t1 = now_ns();
        printf("  push+pop_batch, single thread bulk: %.2f ns per event (%llu events)\n",
               (double)(t1 - t0) / (double)n, (unsigned long long)n);
        free(mem);
    }

    /* Two threads: producer pushes as fast as it can, consumer pops in batches. */
    {
        Cons c;
        memset(&c, 0, sizeof c);
        c.r = new_ring(CAP, &mem);
        atomic_init(&c.stop, 0);
        pthread_t th;
        pthread_create(&th, NULL, consumer, &c);
        uint64_t accepted = 0, refused = 0, seq = 1;
        for (uint32_t k = 0; k < SAMPLES; k++) {
            ArgusEvent e[BATCH];
            int rc[BATCH];
            for (uint32_t j = 0; j < BATCH; j++) e[j] = ev(ARGUS_CLASS_CRITICAL, seq++);
            uint64_t a = now_ns();
            for (uint32_t j = 0; j < BATCH; j++) rc[j] = argus_ring_push(c.r, &e[j]);
            s[k] = (double)(now_ns() - a) / BATCH;
            for (uint32_t j = 0; j < BATCH; j++) { if (rc[j] == ARGUS_OK) accepted++; else refused++; }
        }
        report("push, live consumer thread (CRITICAL)", s, SAMPLES);
        uint64_t n = 20000000ull, p0 = atomic_load(&c.popped), t0 = now_ns();
        for (uint64_t i = 0; i < n; i++, seq++) {
            ArgusEvent e = ev(ARGUS_CLASS_CRITICAL, seq);
            if (argus_ring_push(c.r, &e) == ARGUS_OK) accepted++; else refused++;
        }
        uint64_t t1 = now_ns(), p1 = atomic_load(&c.popped);
        atomic_store_explicit(&c.stop, 1, memory_order_release);
        pthread_join(th, NULL);
        ArgusRingStats st;
        argus_ring_stats(c.r, &st);
        double secs = (double)(t1 - t0) / 1e9;
        printf("  two threads bulk: %.2f ns per push attempt, %.1f M pops/s, accepted %llu, refused (full) %llu, "
               "popped total %llu\n",
               (double)(t1 - t0) / (double)n, (double)(p1 - p0) / secs / 1e6, (unsigned long long)accepted,
               (unsigned long long)refused, (unsigned long long)atomic_load(&c.popped));
        if (st.pushed != accepted || st.popped != atomic_load(&c.popped) || st.critical_overflow != refused) {
            fprintf(stderr, "stats mismatch\n");
            return 1;
        }
        free(mem);
    }
    free(s);
    free(t);
    printf("bench_argus_ring: done\n");
    return 0;
}
