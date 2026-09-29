/*
 * test_argus_determinism.c -- lane D determinism gate + provisional ingest
 * microbenchmark.
 *
 * A 10,000-event synthetic stream (xorshift64*, fixed seed, covers every event
 * kind, non-OK outcomes, sequence repeats, malformed events, table overflow)
 * is fed to two fresh cores in lockstep: return codes and finding bytes must be
 * identical per event, and final state digests and chains equal. The same
 * stream is then fed with two other chunkings (one event at a time with
 * digest/health queries interleaved; and split at event 3333 with the core's
 * memory byte-copied to a different buffer), plus once with a 1-finding output
 * buffer, and all must reach the same state digest.
 *
 * Timing numbers use the STUB hash (FNV), not SHA-256: provisional, Mac only.
 */
#define _GNU_SOURCE
#include "test_common_d.h"
#include <stdlib.h>
#include <time.h>

#define N_EVENTS 10000u
#define N_MACH   20u

static ArgusEvent stream[N_EVENTS];
static _Alignas(16) uint8_t memA[1 << 17], memB[1 << 17], memC[1 << 17], memD[1 << 17], memD2[1 << 17], memE[1 << 17];

static uint64_t rs = 0x9E3779B97F4A7C15ull;
static uint64_t rnd(void)
{
    rs ^= rs >> 12; rs ^= rs << 25; rs ^= rs >> 27;
    return rs * 0x2545F4914F6CDD1Dull;
}
static uint32_t rn(uint32_t n) { return (uint32_t)(rnd() % n); }

static const uint16_t kinds[] = {
    1, 2, 3, 4, 10, 11, 12, 20, 21, 22, 30, 31, 32, 40, 41, 42, 43,
    50, 51, 52, 60, 61, 62, 63, 70, 71, 72, 80
};
#define N_KINDS (sizeof kinds / sizeof kinds[0])

static void gen(void)
{
    static uint64_t seqs[N_MACH][2];
    uint64_t world = 0;
    for (uint32_t i = 0; i < N_EVENTS; i++) {
        ArgusEvent *e = &stream[i];
        memset(e, 0, sizeof *e);
        uint16_t kind = kinds[rn(N_KINDS)];
        uint32_t m = rn(100) < 90 ? rn(4) : rn(N_MACH);
        uint32_t cons = kind == ARGUS_EV_TELEMETRY_DROPPED ? 1u : 0u;
        e->version = ARGUS_ABI_VERSION;
        e->class_ = (uint8_t)(1 + rn(4));
        e->kind = kind;
        e->effect_class = (uint8_t)rn(4);
        uint32_t o = rn(100);
        e->outcome = o < 80 ? ARGUS_OUTCOME_OK : o < 95 ? ARGUS_OUTCOME_DENIED : ARGUS_OUTCOME_ERROR;
        e->flags = (uint16_t)(ARGUS_FLAG_SYNTHETIC | (cons ? ARGUS_FLAG_CONSUMER : 0));
        uint32_t r = rn(100);
        if (r == 0 && seqs[m][cons] > 0)
            e->sequence = seqs[m][cons];                /* replay */
        else if (r == 1 && seqs[m][cons] > 1)
            e->sequence = seqs[m][cons] - 1;            /* reorder */
        else
            e->sequence = ++seqs[m][cons];
        e->tick = i;
        e->principal = 1 + rn(12);
        e->code = (int32_t)rn(3) - 1;
        e->cap_id = rn(261);
        e->cap_generation = 1 + rn(4);
        mid(e->machine_id, m);
        switch (kind) {
        case ARGUS_EV_CAPABILITY_GRANTED: e->object_id = rn(0x400); e->resource = rnd(); break;
        case ARGUS_EV_CREDENTIAL_LEASE_CREATED: case ARGUS_EV_CREDENTIAL_LEASE_USED:
        case ARGUS_EV_CREDENTIAL_LEASE_REVOKED: e->object_id = rn(90); e->resource = rn(16); break;
        case ARGUS_EV_ARTIFACT_ADMITTED: case ARGUS_EV_ARTIFACT_REJECTED:
        case ARGUS_EV_ARTIFACT_ACTIVATED: dg(e->evidence_digest, rn(90)); break;
        case ARGUS_EV_MACHINE_TRUST_CHANGED: e->object_id = rn(8); break;
        case ARGUS_EV_PROVIDER_DISCOVERED: case ARGUS_EV_PROVIDER_CHANGED:
        case ARGUS_EV_PROVIDER_QUARANTINED: case ARGUS_EV_PROVIDER_USED: dg(e->evidence_digest, 1000 + rn(45)); break;
        case ARGUS_EV_WORLD_COMMITTED:
            world = rn(10) == 0 && world > 2 ? world - 2 : world + 1;
            e->world_generation = world; dg(e->evidence_digest, 5000 + (uint32_t)world); break;
        case ARGUS_EV_POLICY_CHANGED: case ARGUS_EV_RUNTIME_BUILD_CHANGED: dg(e->evidence_digest, 7000 + rn(5)); break;
        case ARGUS_EV_TELEMETRY_DROPPED: e->object_id = 1 + rn(4); e->resource = 1 + rn(50); break;
        default: break;
        }
        if (rn(100) == 0)
            e->version = 0;                             /* malformed */
    }
}

typedef struct {
    uint64_t fold, nfind, rc_fold, full, overflow, malformed, seq_anom, det_findings;
    uint8_t state[32], chain[32];
} RunSummary;

static void fold_bytes(uint64_t *h, const void *p, size_t n)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) { *h ^= b[i]; *h *= 0x100000001b3ull; }
}

static void account(RunSummary *s, int rc, const ArgusFinding *f, size_t n)
{
    int32_t r = rc;
    fold_bytes(&s->rc_fold, &r, sizeof r);
    if (rc == ARGUS_ERR_FULL) s->full++;
    if (rc == ARGUS_ERR_OVERFLOW) s->overflow++;
    if (rc == ARGUS_ERR_MALFORMED) s->malformed++;
    for (size_t i = 0; i < n; i++) {
        fold_bytes(&s->fold, &f[i], sizeof f[i]);
        if (f[i].code == ARGUS_F_SEQUENCE_ANOMALY) s->seq_anom++;
        if (f[i].code != ARGUS_F_SEQUENCE_ANOMALY && f[i].code != ARGUS_F_TELEMETRY_LOSS) s->det_findings++;
    }
    s->nfind += n;
}

static void finish(RunSummary *s, const ArgusCore *c)
{
    ArgusCoreHealth h;
    argus_core_state_digest(c, s->state);
    argus_core_health(c, &h);
    memcpy(s->chain, h.chain, 32);
}

static void init_sum(RunSummary *s) { memset(s, 0, sizeof *s); s->fold = s->rc_fold = 0xcbf29ce484222325ull; }

static int same(const RunSummary *a, const RunSummary *b, int with_findings)
{
    if (memcmp(a->state, b->state, 32) || memcmp(a->chain, b->chain, 32)) return 0;
    if (with_findings && (a->fold != b->fold || a->nfind != b->nfind || a->rc_fold != b->rc_fold)) return 0;
    return 1;
}

static uint64_t now_ns(void)
{
#ifdef __APPLE__
    return clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#endif
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

#define BATCH 64u
#define PASSES 20u
static uint64_t batch_samples[PASSES * (N_EVENTS / BATCH + 1)];
static uint64_t single_samples[PASSES * N_EVENTS];

int main(void)
{
    gen();
    stub_detect_mode = 0;

    /* coverage of the generator */
    int seen[81] = {0};
    for (uint32_t i = 0; i < N_EVENTS; i++) seen[stream[i].kind] = 1;
    int covered = 1;
    for (size_t k = 0; k < N_KINDS; k++) covered &= seen[kinds[k]];
    CHECK(covered);

    /* Run 1 vs run 2 in lockstep: byte-identical per event. */
    ArgusCore *A = NULL, *B = NULL;
    CHECK(argus_core_init(&A, memA, sizeof memA) == ARGUS_OK);
    CHECK(argus_core_init(&B, memB, sizeof memB) == ARGUS_OK);
    RunSummary sa, sb; init_sum(&sa); init_sum(&sb);
    static ArgusFinding fa[ARGUS_CORE_MAX_FINDINGS], fb[ARGUS_CORE_MAX_FINDINGS];
    uint64_t mismatch = 0;
    for (uint32_t i = 0; i < N_EVENTS; i++) {
        size_t na = 0, nb = 0;
        int ra = argus_core_ingest(A, &stream[i], fa, ARGUS_CORE_MAX_FINDINGS, &na);
        int rb = argus_core_ingest(B, &stream[i], fb, ARGUS_CORE_MAX_FINDINGS, &nb);
        if (ra != rb || na != nb || memcmp(fa, fb, na * sizeof fa[0]) != 0) mismatch++;
        account(&sa, ra, fa, na);
        account(&sb, rb, fb, nb);
    }
    finish(&sa, A); finish(&sb, B);
    CHECK(mismatch == 0);
    CHECK(same(&sa, &sb, 1));
    CHECK(sa.nfind > 0 && sa.seq_anom > 0 && sa.full > 0 && sa.malformed > 0 && sa.det_findings > 0);

    /* Chunking 1: one at a time, queries interleaved. */
    ArgusCore *C = NULL;
    argus_core_init(&C, memC, sizeof memC);
    RunSummary sc; init_sum(&sc);
    for (uint32_t i = 0; i < N_EVENTS; i++) {
        size_t n = 0;
        int rc = argus_core_ingest(C, &stream[i], fa, ARGUS_CORE_MAX_FINDINGS, &n);
        account(&sc, rc, fa, n);
        if (i % 7 == 0) {
            uint8_t d[32]; ArgusCoreHealth h; ArgusWorldShadow w; ArgusCapShadow cs;
            argus_core_state_digest(C, d); argus_core_health(C, &h);
            argus_core_ops()->world(argus_core_view(C), &w);
            argus_core_ops()->cap(argus_core_view(C), i % 256, &cs);
        }
    }
    finish(&sc, C);
    CHECK(same(&sa, &sc, 1));

    /* Chunking 2: split at 3333, byte-copy the core to another buffer, continue there. */
    ArgusCore *D = NULL;
    argus_core_init(&D, memD, sizeof memD);
    RunSummary sd; init_sum(&sd);
    for (uint32_t i = 0; i < N_EVENTS; i++) {
        if (i == 3333) {
            memcpy(memD2, memD, argus_core_footprint());
            memset(memD, 0xEE, sizeof memD);
            D = (ArgusCore *)(void *)memD2;
        }
        size_t n = 0;
        int rc = argus_core_ingest(D, &stream[i], fa, ARGUS_CORE_MAX_FINDINGS, &n);
        account(&sd, rc, fa, n);
    }
    finish(&sd, D);
    CHECK(same(&sa, &sd, 1));

    /* 1-slot output buffer: findings truncated, state identical. */
    ArgusCore *E = NULL;
    argus_core_init(&E, memE, sizeof memE);
    RunSummary se; init_sum(&se);
    for (uint32_t i = 0; i < N_EVENTS; i++) {
        size_t n = 0;
        int rc = argus_core_ingest(E, &stream[i], fa, 1, &n);
        account(&se, rc, fa, n);
    }
    finish(&se, E);
    CHECK(same(&sa, &se, 0));
    ArgusCoreHealth ha, he; argus_core_health(A, &ha); argus_core_health(E, &he);
    CHECK(ha.findings_emitted == he.findings_emitted && ha.incidents_open == he.incidents_open);

    printf("determinism: %u events, %llu findings (%llu sequence, %llu detector), %llu FULL, %llu malformed, incidents %llu\n",
           N_EVENTS, (unsigned long long)sa.nfind, (unsigned long long)sa.seq_anom,
           (unsigned long long)sa.det_findings, (unsigned long long)sa.full,
           (unsigned long long)sa.malformed, (unsigned long long)ha.incidents_open);
    printf("state digest %02x%02x%02x%02x... (stub hash) identical across lockstep, interleaved, byte-copy split, 1-slot runs\n",
           sa.state[0], sa.state[1], sa.state[2], sa.state[3]);

    /* Provisional microbenchmark (stub hash, not SHA-256). */
    size_t nb_s = 0, ns_s = 0;
    uint64_t total_ns = 0;
    for (uint32_t p = 0; p < PASSES; p++) {
        ArgusCore *X = NULL;
        argus_core_init(&X, memB, sizeof memB);
        for (uint32_t i = 0; i < N_EVENTS; i += BATCH) {
            uint32_t end = i + BATCH < N_EVENTS ? i + BATCH : N_EVENTS;
            uint64_t t0 = now_ns();
            for (uint32_t j = i; j < end; j++) {
                size_t n;
                argus_core_ingest(X, &stream[j], fa, ARGUS_CORE_MAX_FINDINGS, &n);
            }
            uint64_t dt = now_ns() - t0;
            total_ns += dt;
            batch_samples[nb_s++] = dt * 1000u / (end - i);   /* ps per event, for resolution */
        }
        argus_core_init(&X, memB, sizeof memB);
        for (uint32_t i = 0; i < N_EVENTS; i++) {
            size_t n;
            uint64_t t0 = now_ns();
            argus_core_ingest(X, &stream[i], fa, ARGUS_CORE_MAX_FINDINGS, &n);
            single_samples[ns_s++] = now_ns() - t0;
        }
    }
    qsort(batch_samples, nb_s, sizeof batch_samples[0], cmp_u64);
    qsort(single_samples, ns_s, sizeof single_samples[0], cmp_u64);
    printf("bench (PROVISIONAL, stub FNV hash): mean %.1f ns/event; per-%u-event batch p50 %.1f p99 %.1f ns/event; "
           "single-event p50 %llu p99 %llu ns (includes timer overhead)\n",
           (double)total_ns / (PASSES * (double)N_EVENTS), BATCH,
           batch_samples[nb_s / 2] / 1000.0, batch_samples[(nb_s * 99) / 100] / 1000.0,
           (unsigned long long)single_samples[ns_s / 2], (unsigned long long)single_samples[(ns_s * 99) / 100]);

    /* Cost of the stub hash alone (one chain_extend per event), to separate core cost from hash cost. */
    uint8_t hc[32] = {0};
    uint64_t h0 = now_ns();
    for (uint32_t p = 0; p < PASSES; p++)
        for (uint32_t i = 0; i < N_EVENTS; i++)
            argus_chain_extend(hc, &stream[i]);
    double hash_ns = (double)(now_ns() - h0) / (PASSES * (double)N_EVENTS);
    printf("bench: stub chain_extend alone %.1f ns/event (hc %02x) => core excl. hash ~%.1f ns/event\n",
           hash_ns, hc[0], (double)total_ns / (PASSES * (double)N_EVENTS) - hash_ns);

    printf("test_argus_determinism: %d passed, %d failed\n", t_pass, t_fail);
    return t_fail ? 1 : 0;
}
