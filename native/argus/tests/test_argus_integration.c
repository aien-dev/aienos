/*
 * test_argus_integration.c -- ARGUS-0 integration gates (orchestrator-owned).
 *
 * Links ONLY the real lane objects (argus_event.c, argus_ring.c, sha256.c,
 * argus_core.c, argus_detect.c) plus lane E's tests/stub_state.c, used here
 * solely for its corpus generators (argus_corpus_benign / _hostile). No lane D
 * stub. Prints one line per gate:  GATE <NAME> PASS|FAIL <evidence>
 *
 * Run from native/argus (the secret-negative scan walks "." recursively).
 *   test_argus_integration [--bench] [object.o ...]
 * Object files given on the command line are checked with `nm -u` for heap,
 * I/O and clock imports (ARGUS_MEMORY). --bench runs only the ingest timing,
 * longer.
 */
#include "argus_abi.h"
#include "argus_core.h"
#include "argus_detect.h"
#include "sha256.h"
#include "stub_state.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

/* Advance an snprintf append offset without ever passing the end of the buffer:
 * on truncation (or error) the offset is clamped so later appends get size 0. */
static size_t snprintf_advance(size_t off, size_t cap, int n)
{
    if (n < 0 || off >= cap) return off < cap ? off : cap;
    return ((size_t)n >= cap - off) ? cap : off + (size_t)n;
}

#define N_CORPUS      5000u     /* lane E validated the hostile corpus at this size */
#define N_PROBE      10000u     /* capacity probe only (reported, not a gate) */
#define RING_LOG2       10u
#define RING_CAP     (1u << RING_LOG2)
#define FCAP  ARGUS_CORE_MAX_FINDINGS   /* never truncate findings */

/* ---- secret-negative, layout half (same assertions as lane B) ---- */
#define NOT32(f) _Static_assert(sizeof(((ArgusEvent *)0)->f) != 32, "32-byte field: " #f)
NOT32(version); NOT32(class_); NOT32(kind); NOT32(effect_class); NOT32(outcome); NOT32(flags);
NOT32(sequence); NOT32(tick); NOT32(principal); NOT32(code); NOT32(cap_id); NOT32(object_id);
NOT32(cap_generation); NOT32(world_generation); NOT32(resource);
_Static_assert(sizeof(((ArgusEvent *)0)->machine_id) == 32, "machine_id");
_Static_assert(sizeof(((ArgusEvent *)0)->evidence_digest) == 32, "evidence_digest");
_Static_assert(1 + 1 + 2 + 1 + 1 + 2 + 8 + 8 + 4 + 4 + 4 + 4 + 8 + 8 + 8 + 32 + 32 == ARGUS_EVENT_SIZE,
               "field list complete");
_Static_assert(sizeof(ArgusEvent) == ARGUS_EVENT_SIZE, "event is 128 bytes, no padding");

static int gates_failed;

static void gate(const char *name, int pass, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void gate(const char *name, int pass, const char *fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    printf("GATE %s %s %s\n", name, pass ? "PASS" : "FAIL", buf);
    fflush(stdout);
    if (!pass) gates_failed++;
}

static void *xalloc(size_t bytes)
{
    size_t r = (bytes + 63u) & ~(size_t)63u;
    if (r == 0) r = 64;
    void *p = aligned_alloc(64, r);
    if (!p) { fprintf(stderr, "out of memory\n"); exit(2); }
    memset(p, 0, r);
    return p;
}

static void hex(char *out, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]);
    out[2 * n] = 0;
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* ---- a core run: all findings of a stream, in order ---------------------- */
typedef struct {
    ArgusCore *core;
    void *mem;
    ArgusFinding *f;          /* all findings, in emission order */
    size_t nf, fmax;
    uint64_t rc_full, rc_overflow, rc_malformed, rc_other, ingested;
    uint64_t per_code[ARGUS_F_MAX + 1];
} Run;

static void run_init(Run *r, size_t fmax)
{
    memset(r, 0, sizeof *r);
    r->mem = xalloc(argus_core_footprint());
    if (argus_core_init(&r->core, r->mem, argus_core_footprint()) != ARGUS_OK) {
        fprintf(stderr, "argus_core_init failed\n");
        exit(2);
    }
    r->fmax = fmax;
    r->f = xalloc(fmax * sizeof(ArgusFinding));
}

static void run_free(Run *r) { free(r->mem); free(r->f); }

static void run_ingest(Run *r, const ArgusEvent *ev)
{
    ArgusFinding out[FCAP];
    size_t n = 0;
    int rc = argus_core_ingest(r->core, ev, out, FCAP, &n);
    r->ingested++;
    if (rc == ARGUS_ERR_FULL) r->rc_full++;
    else if (rc == ARGUS_ERR_OVERFLOW) r->rc_overflow++;
    else if (rc == ARGUS_ERR_MALFORMED) r->rc_malformed++;
    else if (rc != ARGUS_OK) r->rc_other++;
    for (size_t i = 0; i < n; i++) {
        if (out[i].code <= ARGUS_F_MAX) r->per_code[out[i].code]++;
        if (r->nf < r->fmax) r->f[r->nf] = out[i];
        r->nf++;
    }
}

static void run_digests(const Run *r, uint8_t state[32], uint8_t chain[32])
{
    ArgusCoreHealth h;
    argus_core_state_digest(r->core, state);
    argus_core_health(r->core, &h);
    memcpy(chain, h.chain, 32);
}

/* ---- corpora (static buffers; the generators are not reentrant) ----------- */
static ArgusEvent benign[N_CORPUS];
static ArgusEvent hostile[N_CORPUS];
static ArgusExpectedFinding expect[N_CORPUS];
static size_t n_benign, n_hostile, n_expect;

/* ======================================================================= */
/* ARGUS_EVENT_ABI_PASS                                                     */
/* ======================================================================= */
static ArgusEvent fixed_event(void)   /* identical to lane B tests/test_argus_event.c */
{
    ArgusEvent e;
    memset(&e, 0, sizeof e);
    e.version = ARGUS_ABI_VERSION;
    e.class_ = ARGUS_CLASS_SECURITY;
    e.kind = ARGUS_EV_CAPABILITY_USED;
    e.effect_class = ARGUS_EFFECT_EXTERNAL;
    e.outcome = ARGUS_OUTCOME_OK;
    e.flags = ARGUS_FLAG_SYNTHETIC;
    e.sequence = 0x0102030405060708ull;
    e.tick = 0x1112131415161718ull;
    e.principal = 0x21222324u;
    e.code = -7;
    e.cap_id = 0x31323334u;
    e.object_id = 0x41424344u;
    e.cap_generation = 0x5152535455565758ull;
    e.world_generation = 0x6162636465666768ull;
    e.resource = 0x8182838485868788ull;
    for (unsigned i = 0; i < 32; i++) {
        e.machine_id[i] = (uint8_t)(0xA0 + i);
        e.evidence_digest[i] = (uint8_t)(0xC0 + i);
    }
    return e;
}

static ArgusFinding fixed_finding(void)   /* identical to lane B */
{
    ArgusFinding f;
    memset(&f, 0, sizeof f);
    f.code = ARGUS_F_REVOKED_CAPABILITY_USED;
    f.severity = ARGUS_SEV_HIGH;
    f.confidence = ARGUS_CONF_DETERMINISTIC;
    f.sync_allowed = 1;
    f.containment = ARGUS_CONTAIN_REVOKE_CAPABILITY;
    f.detector = ARGUS_F_REVOKED_CAPABILITY_USED;
    f.sequence = 42;
    f.prior_sequence = 17;
    f.principal = 7;
    f.cap_id = 9;
    f.cap_generation = 3;
    for (unsigned i = 0; i < 32; i++) { f.machine_id[i] = (uint8_t)i; f.event_digest[i] = (uint8_t)(0xFF - i); }
    return f;
}

static size_t round_trip(const ArgusEvent *ev, size_t n, size_t *bad)
{
    size_t ok = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t b[ARGUS_EVENT_SIZE], b2[ARGUS_EVENT_SIZE], d1[32], d2[32];
        ArgusEvent out;
        memset(&out, 0xA5, sizeof out);
        if (argus_event_encode(&ev[i], b) != ARGUS_OK || argus_event_decode(b, &out) != ARGUS_OK ||
            memcmp(&out, &ev[i], sizeof out) != 0 || argus_event_encode(&out, b2) != ARGUS_OK ||
            memcmp(b, b2, sizeof b) != 0) { (*bad)++; continue; }
        argus_event_digest(&ev[i], d1);
        sha256_hash(b, sizeof b, d2);
        if (memcmp(d1, d2, 32) != 0) { (*bad)++; continue; }
        ok++;
    }
    return ok;
}

static void gate_abi(void)
{
    static const char *K_EVENT = "1be29450b792d28426444fceb5e44174e69bb631d5ef6063a870c21929574303";
    static const char *K_CHAIN = "09ea598e432197cc2d6ff341ec57ab403c06312bad2992480b72c6ce87a6d747";
    static const char *K_CHAIN2 = "21b19c9ba36f86074263f49952b64ee8dea9b5ff02ed215555cb1a03bfda78e0";
    static const char *K_FINDING = "b56e133cc6f6cfefe642ce0f1ec74e67c3fee57db2f114257ba04d3d3ee7680a";
    char h[65];
    int ka = 0;
    uint8_t d[32], chain[32] = {0};
    ArgusEvent e = fixed_event();
    argus_event_digest(&e, d); hex(h, d, 32); ka += strcmp(h, K_EVENT) == 0;
    argus_chain_extend(chain, &e); hex(h, chain, 32); ka += strcmp(h, K_CHAIN) == 0;
    e.sequence++;
    argus_chain_extend(chain, &e); hex(h, chain, 32); ka += strcmp(h, K_CHAIN2) == 0;
    ArgusFinding f = fixed_finding();
    argus_finding_digest(&f, d); hex(h, d, 32); ka += strcmp(h, K_FINDING) == 0;

    size_t bad = 0;
    size_t ok_b = round_trip(benign, n_benign, &bad);
    size_t ok_h = round_trip(hostile, n_hostile, &bad);
    /* version byte 2 must be refused as VERSION */
    uint8_t b[ARGUS_EVENT_SIZE];
    ArgusEvent out;
    e = fixed_event();
    argus_event_encode(&e, b);
    b[0] = 2;
    int v2 = argus_event_decode(b, &out) == ARGUS_ERR_VERSION;
    gate("ARGUS_EVENT_ABI_PASS", ka == 4 && bad == 0 && ok_b == n_benign && ok_h == n_hostile && v2,
         "known-answer %d/4 (event 1be29450.., chain 09ea598e.., chain2 21b19c9b.., finding b56e133c..); "
         "round trip encode->decode->re-encode byte-identical + digest==sha256(bytes): benign %zu/%zu, hostile %zu/%zu, "
         "bad %zu; v2 byte rejected=%d",
         ka, ok_b, n_benign, ok_h, n_hostile, bad, v2);
}

/* ======================================================================= */
/* ARGUS_EVENT_SECRET_NEGATIVE_PASS: recursive scan (re-implementation of    */
/* lane B's scan_tree: every regular file under ".", except ./out).          */
/* ======================================================================= */
static int contains_ci(const char *hay, const char *needle)
{
    size_t n = strlen(needle);
    for (; *hay; hay++) if (strncasecmp(hay, needle, n) == 0) return 1;
    return 0;
}

static int scan_tree(const char *dir, const char *word, const char *cap_len, int *files, int *hits, int *dirs)
{
    DIR *d = opendir(dir);
    if (!d) { fprintf(stderr, "cannot open %s (run from native/argus)\n", dir); return -1; }
    (*dirs)++;
    int err = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        if (strcmp(dir, ".") == 0 && strcmp(de->d_name, "out") == 0) continue;
        char path[1024];
        snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
        /* Open first, then fstat the descriptor (no check-then-use race).
         * O_NOFOLLOW: a symlink fails with ELOOP and is skipped, as before;
         * O_NONBLOCK: a FIFO cannot hang the scan (it is skipped below). */
        int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) {
            if (errno == ELOOP || errno == ENXIO) continue;   /* symlink / socket: not scanned */
            err = -1; continue;
        }
        struct stat st;
        if (fstat(fd, &st) != 0) { close(fd); err = -1; continue; }
        if (S_ISDIR(st.st_mode)) { close(fd); if (scan_tree(path, word, cap_len, files, hits, dirs)) err = -1; continue; }
        if (!S_ISREG(st.st_mode)) { close(fd); continue; }
        FILE *fp = fdopen(fd, "r");
        if (!fp) { close(fd); err = -1; continue; }
        (*files)++;
        char line[4096];
        int lineno = 0;
        while (fgets(line, sizeof line, fp)) {
            lineno++;
            if (contains_ci(line, word) || strstr(line, cap_len)) {
                (*hits)++;
                printf("  secret-negative hit: %s:%d\n", path, lineno);
            }
        }
        fclose(fp);
    }
    closedir(d);
    return err;
}

static void gate_secret(void)
{
    char word[8], cap_len[32];
    snprintf(word, sizeof word, "%s%s", "to", "ken");
    snprintf(cap_len, sizeof cap_len, "%s%s%s", "AIENOS_CAP_", "TO", "KEN_LEN");
    int files = 0, hits = 0, dirs = 0;
    int err = scan_tree(".", word, cap_len, &files, &hits, &dirs);
    gate("ARGUS_EVENT_SECRET_NEGATIVE_PASS", err == 0 && hits == 0 && files >= 20,
         "%d files in %d dirs under native/argus (recursive incl. docs/ tests/, out/ excluded), %d hits, scan errors %d; "
         "static: 15 event fields != 32 bytes, only machine_id/evidence_digest are 32, field sum == 128",
         files, dirs, hits, err ? 1 : 0);
}

/* ======================================================================= */
/* Ring path: producer thread -> ring -> consumer thread -> core             */
/* ======================================================================= */
typedef struct {
    ArgusRing *ring;
    const ArgusEvent *ev;
    size_t n;
    uint32_t throttle_depth;       /* 0 = unthrottled burst */
    uint64_t accepted, refused_rc, other_rc;
    _Atomic int done;
} Producer;

typedef struct {
    ArgusRing *ring;
    _Atomic int *prod_done;
    Run *run;
    uint64_t popped, drop_events, next_seq;
    uint64_t dropped_by_class[ARGUS_CLASS_MAX + 1];     /* sum of TELEMETRY_DROPPED resource */
    uint64_t drop_events_by_class[ARGUS_CLASS_MAX + 1];
    uint64_t loss_expected, loss_seen, loss_wrong_sev;
    unsigned sleep_us;             /* slow consumer: sleep after each batch */
    size_t batch;
} Consumer;

static void *producer_main(void *arg)
{
    Producer *p = arg;
    for (size_t i = 0; i < p->n; i++) {
        if (p->throttle_depth) {
            for (;;) {
                ArgusRingStats s;
                argus_ring_stats(p->ring, &s);
                if (s.depth < p->throttle_depth) break;
                sched_yield();
            }
        }
        int rc = argus_ring_push(p->ring, &p->ev[i]);
        if (rc == ARGUS_OK) p->accepted++;
        else if (rc == ARGUS_ERR_FULL) p->refused_rc++;
        else p->other_rc++;
    }
    atomic_store_explicit(&p->done, 1, memory_order_release);
    return NULL;
}

/* Ingest one synthesized drop event and check the core's TELEMETRY_LOSS answer. */
static void consume_drop(Consumer *c, const ArgusEvent *d)
{
    size_t before = c->run->nf;
    run_ingest(c->run, d);
    c->drop_events++;
    if (d->object_id <= ARGUS_CLASS_MAX) {
        c->dropped_by_class[d->object_id] += d->resource;
        c->drop_events_by_class[d->object_id]++;
    }
    int want = d->object_id == ARGUS_CLASS_CRITICAL || d->object_id == ARGUS_CLASS_SECURITY;
    uint8_t want_sev = d->object_id == ARGUS_CLASS_CRITICAL ? ARGUS_SEV_CRITICAL : ARGUS_SEV_HIGH;
    c->loss_expected += (uint64_t)want;
    for (size_t i = before; i < c->run->nf && i < c->run->fmax; i++) {
        if (c->run->f[i].code == ARGUS_F_TELEMETRY_LOSS) {
            c->loss_seen++;
            if (c->run->f[i].severity != want_sev) c->loss_wrong_sev++;
        }
    }
}

static void consumer_drain(Consumer *c)
{
    ArgusEvent drops[ARGUS_CLASS_MAX];
    size_t nd = argus_ring_drain_drops(c->ring, drops, ARGUS_CLASS_MAX, &c->next_seq);
    for (size_t i = 0; i < nd; i++) consume_drop(c, &drops[i]);
}

/* One consumer step: pop a batch, ingest it, drain drops. Returns events popped. */
static size_t consumer_step(Consumer *c, ArgusEvent *buf)
{
    size_t n = argus_ring_pop_batch(c->ring, buf, c->batch);
    for (size_t i = 0; i < n; i++) run_ingest(c->run, &buf[i]);
    c->popped += n;
    consumer_drain(c);
    return n;
}

static void *consumer_main(void *arg)
{
    Consumer *c = arg;
    ArgusEvent buf[64];
    for (;;) {
        int done = atomic_load_explicit(c->prod_done, memory_order_acquire);
        size_t n = consumer_step(c, buf);
        if (n == 0 && done) break;    /* producer finished before this empty pop: empty for good */
        if (c->sleep_us) {
            struct timespec ts = { 0, (long)c->sleep_us * 1000L };
            nanosleep(&ts, NULL);
        } else if (n == 0) {
            sched_yield();
        }
    }
    return NULL;
}

typedef struct {
    Producer p;
    Consumer c;
    ArgusRingStats stats;
} RingRun;

static void ring_run(RingRun *rr, Run *run, const ArgusEvent *ev, size_t n, uint32_t throttle)
{
    memset(rr, 0, sizeof *rr);
    size_t bytes = argus_ring_footprint(RING_CAP);
    void *mem = xalloc(bytes);
    ArgusRing *ring;
    if (argus_ring_init(&ring, mem, bytes, RING_CAP) != ARGUS_OK) { fprintf(stderr, "ring init\n"); exit(2); }
    rr->p.ring = ring; rr->p.ev = ev; rr->p.n = n; rr->p.throttle_depth = throttle;
    atomic_init(&rr->p.done, 0);
    rr->c.ring = ring; rr->c.prod_done = &rr->p.done; rr->c.run = run; rr->c.batch = 64;
    rr->c.next_seq = 1;
    pthread_t tp, tc;
    pthread_create(&tc, NULL, consumer_main, &rr->c);
    pthread_create(&tp, NULL, producer_main, &rr->p);
    pthread_join(tp, NULL);
    pthread_join(tc, NULL);
    argus_ring_stats(ring, &rr->stats);
    free(mem);
}

static uint64_t sum_refused(const ArgusRingStats *s)
{
    uint64_t t = s->critical_overflow;
    for (unsigned c = 1; c <= ARGUS_CLASS_MAX; c++) t += s->refused[c];
    return t;
}

/* Identity checks shared by transport runs. */
static int ring_identity(const RingRun *rr, char *why, size_t whylen)
{
    const ArgusRingStats *s = &rr->stats;
    uint64_t refused = sum_refused(s);
    int ok = 1;
    ok &= rr->p.other_rc == 0;
    ok &= s->pushed == rr->p.accepted;
    ok &= s->pushed + refused == rr->p.n;
    ok &= rr->p.refused_rc == refused;
    ok &= s->popped == s->pushed && rr->c.popped == s->pushed;
    ok &= s->refused[ARGUS_CLASS_CRITICAL] == 0;
    /* every refusal is reported by a TELEMETRY_DROPPED, per class */
    ok &= rr->c.dropped_by_class[ARGUS_CLASS_CRITICAL] == s->critical_overflow;
    for (unsigned c = 2; c <= ARGUS_CLASS_MAX; c++) ok &= rr->c.dropped_by_class[c] == s->refused[c];
    ok &= rr->c.loss_seen == rr->c.loss_expected && rr->c.loss_wrong_sev == 0;
    snprintf(why, whylen,
             "attempts %zu = pushed %llu + refused %llu (SEC %llu AUD %llu INF %llu, crit_overflow %llu); popped %llu; "
             "drop events %llu reporting %llu lost; TELEMETRY_LOSS findings %llu/%llu expected",
             rr->p.n, (unsigned long long)s->pushed, (unsigned long long)refused,
             (unsigned long long)s->refused[2], (unsigned long long)s->refused[3], (unsigned long long)s->refused[4],
             (unsigned long long)s->critical_overflow, (unsigned long long)s->popped,
             (unsigned long long)rr->c.drop_events,
             (unsigned long long)(rr->c.dropped_by_class[1] + rr->c.dropped_by_class[2] + rr->c.dropped_by_class[3] +
                                  rr->c.dropped_by_class[4]),
             (unsigned long long)rr->c.loss_seen, (unsigned long long)rr->c.loss_expected);
    return ok;
}

/* Direct and ring-path hostile runs, shared by TRANSPORT, DETERMINISM, HARD_INVARIANTS. */
static Run direct_h, ring_h, burst_h;
static RingRun rr_fast, rr_burst;

static void gate_transport(void)
{
    char w1[512], w2[512];
    run_init(&ring_h, (size_t)N_CORPUS * FCAP);
    ring_run(&rr_fast, &ring_h, hostile, n_hostile, RING_CAP / 4);
    int id1 = ring_identity(&rr_fast, w1, sizeof w1);
    int none_refused = sum_refused(&rr_fast.stats) == 0 && rr_fast.c.drop_events == 0;

    run_init(&burst_h, (size_t)N_CORPUS * FCAP + 64);
    ring_run(&rr_burst, &burst_h, hostile, n_hostile, 0);
    int id2 = ring_identity(&rr_burst, w2, sizeof w2);

    gate("ARGUS_EVENT_TRANSPORT_PASS", id1 && none_refused && id2 && ring_h.ingested == n_hostile,
         "hostile seed 1, ring %u. fast consumer (producer keeps depth < %u): %s; nothing refused=%d. "
         "burst (unthrottled producer): %s; identity=%d",
         RING_CAP, RING_CAP / 4, w1, none_refused, w2, id2);
}

/* ======================================================================= */
/* ARGUS_TRANSPORT_SATURATION_PASS                                          */
/* ======================================================================= */
/* Each class is driven by a kind whose floor (argus_event_min_class) is that
 * class, so every watermark is exercised by rule-abiding traffic:
 *   INFORMATIONAL: no v1 kind has an INFORMATIONAL floor (design fact), so a
 *                  non-v1 kind (0x7FFF) is used. The ring is transport and has
 *                  no floor for it; the core rejects it (MALFORMED_EVENT, 16),
 *                  and the gate counts those findings exactly.
 *   SECURITY:      CAPABILITY_DENIED (SECURITY floor), no finding.
 *   CRITICAL:      CREDENTIAL_LEASE_REVOKED of an unknown lease (CRITICAL floor),
 *                  not applied, no finding, no state growth. */
#define FLOOD_KIND_INF 0x7FFFu
static uint16_t flood_kind(uint8_t cls)
{
    return cls == ARGUS_CLASS_INFORMATIONAL ? FLOOD_KIND_INF
         : cls == ARGUS_CLASS_CRITICAL ? ARGUS_EV_CREDENTIAL_LEASE_REVOKED
         : ARGUS_EV_CAPABILITY_DENIED;
}

static ArgusEvent flood_event(uint64_t seq, uint8_t cls)
{
    ArgusEvent e;
    memset(&e, 0, sizeof e);
    e.version = ARGUS_ABI_VERSION;
    e.class_ = cls;
    e.kind = flood_kind(cls);
    e.effect_class = ARGUS_EFFECT_NONE;
    e.outcome = ARGUS_OUTCOME_DENIED;
    e.flags = ARGUS_FLAG_SYNTHETIC;
    e.sequence = seq;
    e.tick = seq;
    e.principal = 1;
    e.code = -7;   /* authority: rights */
    e.cap_id = ARGUS_CAP_NONE;   /* v1.1: no capability (cap 0 is the office slot) */
    return e;
}

/* class pattern: 5 INFORMATIONAL, 2 SECURITY, 1 CRITICAL per 8 */
static uint8_t flood_class(size_t i)
{
    unsigned k = (unsigned)(i & 7u);
    return k < 5 ? ARGUS_CLASS_INFORMATIONAL : k < 7 ? ARGUS_CLASS_SECURITY : ARGUS_CLASS_CRITICAL;
}

typedef struct {
    ArgusRing *ring;
    const ArgusEvent *ev;
    size_t n;
    uint64_t first_refusal_idx[ARGUS_CLASS_MAX + 1];   /* attempt index + 1, 0 = never */
    uint64_t refused_below_limit[ARGUS_CLASS_MAX + 1];  /* refused although depth-before < class limit */
    uint64_t sec_refused_while_info_accepting;
    uint64_t crit_refused_below_full;
    uint64_t max_depth_seen;
    _Atomic int done;
} SatProducer;

static void *sat_producer_main(void *arg)
{
    SatProducer *p = arg;
    uint32_t lim[ARGUS_CLASS_MAX + 1] = {0};
    for (unsigned c = 1; c <= ARGUS_CLASS_MAX; c++) lim[c] = argus_ring_saturation_point(RING_CAP, (uint8_t)c);
    for (size_t i = 0; i < p->n; i++) {
        ArgusRingStats s;
        argus_ring_stats(p->ring, &s);     /* depth can only fall between this read and the push */
        if (s.depth > p->max_depth_seen) p->max_depth_seen = s.depth;
        unsigned cls = p->ev[i].class_;
        int rc = argus_ring_push(p->ring, &p->ev[i]);
        if (rc == ARGUS_ERR_FULL) {
            if (!p->first_refusal_idx[cls]) p->first_refusal_idx[cls] = i + 1;
            if (s.depth < lim[cls]) p->refused_below_limit[cls]++;
            if (cls == ARGUS_CLASS_SECURITY && s.depth < lim[ARGUS_CLASS_INFORMATIONAL])
                p->sec_refused_while_info_accepting++;
            if (cls == ARGUS_CLASS_CRITICAL && s.depth < RING_CAP) p->crit_refused_below_full++;
        }
    }
    atomic_store_explicit(&p->done, 1, memory_order_release);
    return NULL;
}

typedef struct {
    Consumer c;
    _Atomic int stall;            /* consumer pops nothing while set */
} SatConsumer;

static void *sat_consumer_main(void *arg)
{
    SatConsumer *sc = arg;
    Consumer *c = &sc->c;
    ArgusEvent buf[64];
    for (;;) {
        int done = atomic_load_explicit(c->prod_done, memory_order_acquire);
        if (atomic_load_explicit(&sc->stall, memory_order_acquire) && !done) { sched_yield(); continue; }
        size_t n = consumer_step(c, buf);
        if (n == 0 && done) break;
        struct timespec ts = { 0, (long)c->sleep_us * 1000L };
        nanosleep(&ts, NULL);
    }
    return NULL;
}

static void gate_saturation(void)
{
    const size_t N = 200000;
    ArgusEvent *ev = xalloc(N * sizeof *ev);
    for (size_t i = 0; i < N; i++) ev[i] = flood_event(i + 1, flood_class(i));

    size_t n_inf = 0;
    for (size_t i = 0; i < N; i++) n_inf += ev[i].class_ == ARGUS_CLASS_INFORMATIONAL;

    /* pre-check: through a real core, the SEC/CRIT flood kinds yield no finding
     * and each INF (non-v1) event yields exactly one MALFORMED_EVENT */
    Run pre;
    run_init(&pre, 8192);
    size_t pre_inf = 0;
    for (size_t i = 0; i < 4096; i++) { run_ingest(&pre, &ev[i]); pre_inf += ev[i].class_ == ARGUS_CLASS_INFORMATIONAL; }
    size_t pre_findings = pre.nf - pre.per_code[ARGUS_F_MALFORMED_EVENT];
    int pre_malformed_ok = pre.per_code[ARGUS_F_MALFORMED_EVENT] == pre_inf;
    run_free(&pre);

    Run run;
    run_init(&run, N * 2 + 4096);
    size_t bytes = argus_ring_footprint(RING_CAP);
    void *mem = xalloc(bytes);
    ArgusRing *ring;
    argus_ring_init(&ring, mem, bytes, RING_CAP);

    SatProducer p;
    memset(&p, 0, sizeof p);
    p.ring = ring; p.ev = ev; p.n = N;
    atomic_init(&p.done, 0);
    SatConsumer sc;
    memset(&sc, 0, sizeof sc);
    sc.c.ring = ring; sc.c.prod_done = &p.done; sc.c.run = &run; sc.c.batch = 8; sc.c.sleep_us = 20;
    sc.c.next_seq = 1;
    atomic_init(&sc.stall, 1);   /* phase 1: consumer stalled until the ring is full */

    pthread_t tp, tc;
    pthread_create(&tc, NULL, sat_consumer_main, &sc);
    pthread_create(&tp, NULL, sat_producer_main, &p);
    /* release the consumer once the producer has driven the ring to 100% (or finished) */
    for (;;) {
        ArgusRingStats s;
        argus_ring_stats(ring, &s);
        if (s.depth >= RING_CAP || atomic_load_explicit(&p.done, memory_order_acquire)) break;
        sched_yield();
    }
    atomic_store_explicit(&sc.stall, 0, memory_order_release);
    pthread_join(tp, NULL);
    pthread_join(tc, NULL);
    ArgusRingStats s;
    argus_ring_stats(ring, &s);

    uint64_t loss_total = run.per_code[ARGUS_F_TELEMETRY_LOSS];
    uint64_t malformed = run.per_code[ARGUS_F_MALFORMED_EVENT];
    uint64_t other_findings = run.nf - loss_total - malformed;

    int ok = 1;
    ok &= pre_findings == 0 && pre_malformed_ok;
    ok &= s.refused[0] == 0;                               /* every flood event met its class floor */
    ok &= malformed == n_inf - s.refused[ARGUS_CLASS_INFORMATIONAL];   /* each accepted INF -> one code 16 */
    ok &= p.refused_below_limit[1] == 0 && p.refused_below_limit[2] == 0 && p.refused_below_limit[4] == 0;
    ok &= p.sec_refused_while_info_accepting == 0 && p.crit_refused_below_full == 0;
    ok &= p.first_refusal_idx[ARGUS_CLASS_INFORMATIONAL] != 0;
    ok &= p.first_refusal_idx[ARGUS_CLASS_SECURITY] == 0 ||
          p.first_refusal_idx[ARGUS_CLASS_SECURITY] > p.first_refusal_idx[ARGUS_CLASS_INFORMATIONAL];
    ok &= p.max_depth_seen == RING_CAP;
    ok &= s.pushed + sum_refused(&s) == N && s.popped == s.pushed;
    ok &= sc.c.dropped_by_class[1] == s.critical_overflow && sc.c.dropped_by_class[2] == s.refused[2] &&
          sc.c.dropped_by_class[3] == s.refused[3] && sc.c.dropped_by_class[4] == s.refused[4];
    ok &= sc.c.loss_seen == sc.c.loss_expected && sc.c.loss_wrong_sev == 0 && loss_total == sc.c.loss_seen;
    ok &= other_findings == 0;
    gate("ARGUS_TRANSPORT_SATURATION_PASS", ok,
         "%zu attempts (5 INF 0x7FFF : 2 SEC CAPABILITY_DENIED : 1 CRIT LEASE_REVOKED), ring %u, consumer stalled to 100%% then 8/20us; limits INF %u SEC %u CRIT %u; "
         "max depth seen %llu; refused INF %llu SEC %llu CRIT(overflow) %llu; first refusal idx INF %llu SEC %llu CRIT %llu; "
         "refused below limit INF/SEC/CRIT %llu/%llu/%llu; SEC refused while INF accepting %llu; CRIT refused below 100%% %llu; "
         "drop events %llu (CRIT-class %llu SEC-class %llu INF-class %llu) -> TELEMETRY_LOSS %llu/%llu expected, wrong sev %llu; "
         "INF (non-v1 kind) delivered -> MALFORMED_EVENT %llu/%llu expected; ring malformed refusals %llu; "
         "other findings %llu (flood pre-check %zu)",
         N, RING_CAP, argus_ring_saturation_point(RING_CAP, 4), argus_ring_saturation_point(RING_CAP, 2),
         argus_ring_saturation_point(RING_CAP, 1), (unsigned long long)p.max_depth_seen,
         (unsigned long long)s.refused[4], (unsigned long long)s.refused[2], (unsigned long long)s.critical_overflow,
         (unsigned long long)p.first_refusal_idx[4], (unsigned long long)p.first_refusal_idx[2],
         (unsigned long long)p.first_refusal_idx[1], (unsigned long long)p.refused_below_limit[4],
         (unsigned long long)p.refused_below_limit[2], (unsigned long long)p.refused_below_limit[1],
         (unsigned long long)p.sec_refused_while_info_accepting, (unsigned long long)p.crit_refused_below_full,
         (unsigned long long)sc.c.drop_events, (unsigned long long)sc.c.drop_events_by_class[1],
         (unsigned long long)sc.c.drop_events_by_class[2], (unsigned long long)sc.c.drop_events_by_class[4],
         (unsigned long long)sc.c.loss_seen, (unsigned long long)sc.c.loss_expected,
         (unsigned long long)sc.c.loss_wrong_sev, (unsigned long long)malformed,
         (unsigned long long)(n_inf - s.refused[ARGUS_CLASS_INFORMATIONAL]), (unsigned long long)s.refused[0],
         (unsigned long long)other_findings, pre_findings);
    run_free(&run);
    free(mem);
    free(ev);
}

/* ======================================================================= */
/* ARGUS_CORE_DETERMINISM_PASS                                              */
/* ======================================================================= */
static void gate_determinism(void)
{
    /* direct_h was filled in main() before the ring runs */
    uint8_t s1[32], c1[32], s2[32], c2[32];
    run_digests(&direct_h, s1, c1);
    run_digests(&ring_h, s2, c2);
    int zero_refused = sum_refused(&rr_fast.stats) == 0 && rr_fast.c.drop_events == 0;
    int same_n = direct_h.nf == ring_h.nf && direct_h.nf <= direct_h.fmax;
    int same_f = same_n && memcmp(direct_h.f, ring_h.f, direct_h.nf * sizeof(ArgusFinding)) == 0;
    int same_s = memcmp(s1, s2, 32) == 0, same_c = memcmp(c1, c2, 32) == 0;
    /* a third, fresh direct core: repeatability */
    Run again;
    run_init(&again, (size_t)N_CORPUS * FCAP);
    for (size_t i = 0; i < n_hostile; i++) run_ingest(&again, &hostile[i]);
    uint8_t s3[32], c3[32];
    run_digests(&again, s3, c3);
    int same3 = again.nf == direct_h.nf && memcmp(again.f, direct_h.f, again.nf * sizeof(ArgusFinding)) == 0 &&
                memcmp(s3, s1, 32) == 0 && memcmp(c3, c1, 32) == 0;
    run_free(&again);
    uint8_t fd[32];
    sha256_hash((const uint8_t *)direct_h.f, direct_h.nf * sizeof(ArgusFinding), fd);
    char hs[65], hc[65], hf[65];
    hex(hs, s1, 32); hex(hc, c1, 32); hex(hf, fd, 32);
    gate("ARGUS_CORE_DETERMINISM_PASS", zero_refused && same_f && same_s && same_c && same3 && direct_h.nf > 0,
         "hostile seed 1 (%zu events): direct vs ring path (0 refused=%d): findings %zu vs %zu byte-identical=%d, "
         "state digest equal=%d, chain equal=%d; third fresh direct core identical=%d; state %.16s.. chain %.16s.. "
         "findings-bytes sha256 %.16s..",
         n_hostile, zero_refused, direct_h.nf, ring_h.nf, same_f, same_s, same_c, same3, hs, hc, hf);
}

/* ======================================================================= */
/* sequence analysis for code 12: streams keyed like the core,              */
/* (machine_id, ARGUS_STREAM_OF(flags), CONSUMER bit)  (v1.1)                */
/* ======================================================================= */
static int per_stream_strictly_increasing(const ArgusEvent *ev, size_t n, size_t *streams)
{
    enum { MAXS = 4096 };
    static uint8_t ids[MAXS][ARGUS_MACHINE_ID_LEN];
    static uint8_t cons[MAXS];
    static uint16_t strm[MAXS];
    static uint64_t last[MAXS];
    size_t ns = 0;
    int ok = 1;
    for (size_t i = 0; i < n; i++) {
        uint8_t cb = (ev[i].flags & ARGUS_FLAG_CONSUMER) ? 1 : 0;
        uint16_t st = ARGUS_STREAM_OF(ev[i].flags);
        size_t k;
        for (k = 0; k < ns; k++)
            if (cons[k] == cb && strm[k] == st && memcmp(ids[k], ev[i].machine_id, ARGUS_MACHINE_ID_LEN) == 0) break;
        if (k == ns) {
            if (ns == MAXS) return -1;
            memcpy(ids[ns], ev[i].machine_id, ARGUS_MACHINE_ID_LEN);
            cons[ns] = cb;
            strm[ns] = st;
            last[ns] = ev[i].sequence;
            ns++;
            continue;
        }
        if (ev[i].sequence <= last[k]) ok = 0;
        else last[k] = ev[i].sequence;
    }
    *streams = ns;
    return ok;
}

/* ======================================================================= */
/* ARGUS_HARD_INVARIANTS_PASS                                               */
/* ======================================================================= */
static int expected_has(uint64_t seq, uint16_t code)
{
    for (size_t i = 0; i < n_expect; i++) if (expect[i].sequence == seq && expect[i].code == code) return 1;
    return 0;
}

/* Explain findings that are not in the expected list (all findings, for a
 * benign stream): re-ingest through a fresh core, then attribute each
 * unexpected code 4 / code 6 / code 11 to a known integration cause. */
static void explain_unexpected(const char *label, const ArgusEvent *ev, size_t n, int use_expect)
{
    static uint8_t full_at[N_PROBE];
    Run r;
    run_init(&r, (size_t)n * FCAP);
    size_t *first = xalloc((n + 1) * sizeof *first);   /* index of the first finding of event i */
    for (size_t i = 0; i < n; i++) {
        uint64_t before = r.rc_full;
        first[i] = r.nf;
        run_ingest(&r, &ev[i]);
        full_at[i] = r.rc_full != before;
    }
    first[n] = r.nf;
    uint64_t c6 = 0, c6_revive = 0, c4 = 0, c4_full = 0, c11 = 0, other = 0;
    uint64_t full_kind[ARGUS_EV_KIND_MAX + 1] = {0};
    for (size_t i = 0; i < n; i++) {
        if (full_at[i] && ev[i].kind <= ARGUS_EV_KIND_MAX) full_kind[ev[i].kind]++;
        for (size_t j = first[i]; j < first[i + 1] && j < r.fmax; j++) {
            uint16_t code = r.f[j].code;
            if (use_expect && expected_has(r.f[j].sequence, code)) continue;
            if (code == ARGUS_F_CREDENTIAL_SCOPE_VIOLATION) {
                int revoked = 0, recreated = 0;
                for (size_t p = 0; p < i; p++) {
                    if (ev[p].object_id != ev[i].object_id || ev[p].outcome != ARGUS_OUTCOME_OK) continue;
                    if (ev[p].kind == ARGUS_EV_CREDENTIAL_LEASE_REVOKED) revoked = 1;
                    if (ev[p].kind == ARGUS_EV_CREDENTIAL_LEASE_CREATED && revoked) recreated = 1;
                }
                c6++;
                c6_revive += (uint64_t)recreated;
            } else if (code == ARGUS_F_ARTIFACT_DIGEST_UNEXPECTED) {
                int adm_full = 0;
                for (size_t p = 0; p < i && !adm_full; p++)
                    adm_full = full_at[p] && (ev[p].kind == ARGUS_EV_ARTIFACT_ADMITTED ||
                                              ev[p].kind == ARGUS_EV_ARTIFACT_REJECTED) &&
                               memcmp(ev[p].evidence_digest, ev[i].evidence_digest, ARGUS_DIGEST_LEN) == 0;
                c4++;
                c4_full += (uint64_t)adm_full;
            } else if (code == ARGUS_F_TELEMETRY_LOSS) {
                c11++;
            } else {
                other++;
            }
        }
    }
    char fk[256] = "";
    size_t off = 0;
    for (unsigned k = 0; k <= ARGUS_EV_KIND_MAX; k++)
        if (full_kind[k])
            off = snprintf_advance(off, sizeof fk, snprintf(fk + off, sizeof fk - off, " kind%u=%llu", k, (unsigned long long)full_kind[k]));
    printf("EXPLAIN %s: unexpected code 6 %llu, of which %llu on a lease id REVOKED then CREATED again earlier "
           "(core keeps it REVOKED, argus_core.c:427; corpus reuses lease ids); unexpected code 4 %llu, of which %llu "
           "on an artifact whose ADMITTED/REJECTED hit ARGUS_ERR_FULL (ARGUS_CORE_ARTIFACTS 64 < corpus G_ARTIFACTS 96); "
           "code 11 %llu (== ingest rc FULL %llu, by kind:%s); other unexpected %llu\n",
           label, (unsigned long long)c6, (unsigned long long)c6_revive, (unsigned long long)c4,
           (unsigned long long)c4_full, (unsigned long long)c11, (unsigned long long)r.rc_full, fk[0] ? fk : " none",
           (unsigned long long)other);
    free(first);
    run_free(&r);
}

/* Hard codes: every finding code except 11 (telemetry loss) and 12 (sequence
 * anomaly), which have their own checks below. Since the hostile-review round
 * this includes 13..16 (authority replay, subject mismatch, trust escalation,
 * malformed event); lane E's corpus injects 14 and 15. */
static int hard_code(unsigned c)
{
    return c >= 1 && c <= ARGUS_F_MAX && c != ARGUS_F_TELEMETRY_LOSS && c != ARGUS_F_SEQUENCE_ANOMALY;
}

static void gate_hard_invariants(void)
{
    uint64_t exp_by[ARGUS_F_MAX + 1] = {0}, det_by[ARGUS_F_MAX + 1] = {0}, unexp_by[ARGUS_F_MAX + 1] = {0};
    for (size_t i = 0; i < n_expect; i++) {
        uint16_t code = expect[i].code;
        if (code > ARGUS_F_MAX) continue;
        exp_by[code]++;
        int found = 0;
        for (size_t j = 0; j < direct_h.nf && !found; j++)
            found = direct_h.f[j].sequence == expect[i].sequence && direct_h.f[j].code == code;
        if (found) det_by[code]++;
        else printf("  missed expected finding: seq %llu code %u\n", (unsigned long long)expect[i].sequence, code);
    }
    uint64_t unexpected_hard = 0;
    for (size_t j = 0; j < direct_h.nf; j++) {
        uint16_t code = direct_h.f[j].code;
        if (hard_code(code) && !expected_has(direct_h.f[j].sequence, code)) {
            unexpected_hard++;
            unexp_by[code]++;
            if (unexpected_hard <= 10)
                printf("  unexpected finding: seq %llu code %u\n", (unsigned long long)direct_h.f[j].sequence, code);
        }
    }
    size_t streams = 0;
    int incr = per_stream_strictly_increasing(hostile, n_hostile, &streams);
    uint64_t seq12 = direct_h.per_code[ARGUS_F_SEQUENCE_ANOMALY];
    uint64_t loss11 = direct_h.per_code[ARGUS_F_TELEMETRY_LOSS];
    int missing = 0;
    printf("  hard invariants, hostile seed 1 (%zu events, %zu injected):\n", n_hostile, n_expect);
    printf("    code  detected/expected  unexpected\n");
    for (unsigned c = 1; c <= ARGUS_F_MAX; c++) {
        if (!hard_code(c)) continue;
        printf("    %4u  %8llu/%-8llu  %llu\n", c, (unsigned long long)det_by[c], (unsigned long long)exp_by[c],
               (unsigned long long)unexp_by[c]);
        if (det_by[c] != exp_by[c]) missing = 1;
    }
    char table[512];
    size_t off = 0;
    for (unsigned c = 1; c <= ARGUS_F_MAX; c++)
        if (hard_code(c))
            off = snprintf_advance(off, sizeof table, snprintf(table + off, sizeof table - off, "%s%u:%llu/%llu", c > 1 ? " " : "", c,
                                (unsigned long long)det_by[c], (unsigned long long)exp_by[c]));
    /* 12 on strictly increasing per-stream sequences is an integration bug; 11 means shadow tables overflowed */
    int seq_ok = !(seq12 > 0 && incr == 1);
    if (unexpected_hard || loss11 || seq12) explain_unexpected("hostile seed 1", hostile, n_hostile, 1);
    gate("ARGUS_HARD_INVARIANTS_PASS",
         !missing && unexpected_hard == 0 && seq_ok && loss11 == 0 && direct_h.rc_full == 0 && direct_h.rc_overflow == 0,
         "real core + real detectors, hostile seed 1: code detected/expected [%s]; all %zu injected found=%d; "
         "unexpected hard (1..16 except 11/12) %llu; code 12 findings %llu (corpus sequences strictly increasing per "
         "(machine_id,stream,consumer) stream: %s, %zu streams); code 11 findings %llu; ingest rc FULL %llu OVERFLOW %llu",
         table, n_expect, !missing, (unsigned long long)unexpected_hard, (unsigned long long)seq12,
         incr == 1 ? "yes" : incr == 0 ? "NO" : "unknown", streams, (unsigned long long)loss11,
         (unsigned long long)direct_h.rc_full, (unsigned long long)direct_h.rc_overflow);
}

/* ======================================================================= */
/* ARGUS_FALSE_POSITIVE_BASELINE_PASS                                       */
/* ======================================================================= */
static void gate_false_positive(void)
{
    uint64_t total = 0, by[ARGUS_F_MAX + 1] = {0}, full = 0, events = 0;
    int incr_all = 1;
    char per_seed[256];
    size_t off = 0;
    for (uint64_t seed = 1; seed <= 9; seed++) {
        size_t n = argus_corpus_benign(benign, N_CORPUS, seed);
        size_t streams;
        if (per_stream_strictly_increasing(benign, n, &streams) != 1) incr_all = 0;
        Run r;
        run_init(&r, (size_t)N_CORPUS * FCAP);
        for (size_t i = 0; i < n; i++) run_ingest(&r, &benign[i]);
        for (unsigned c = 0; c <= ARGUS_F_MAX; c++) by[c] += r.per_code[c];
        for (size_t j = 0; j < r.nf && j < 3; j++)
            printf("  benign seed %llu finding: seq %llu code %u\n", (unsigned long long)seed,
                   (unsigned long long)r.f[j].sequence, r.f[j].code);
        if (r.nf) {
            char label[32];
            snprintf(label, sizeof label, "benign seed %llu", (unsigned long long)seed);
            explain_unexpected(label, benign, n, 0);
        }
        total += r.nf;
        full += r.rc_full;
        events += n;
        off = snprintf_advance(off, sizeof per_seed, snprintf(per_seed + off, sizeof per_seed - off, "%s%zu", seed > 1 ? "," : "", r.nf));
        run_free(&r);
    }
    /* restore seed-1 benign corpus for the timing below */
    n_benign = argus_corpus_benign(benign, N_CORPUS, 1);
    gate("ARGUS_FALSE_POSITIVE_BASELINE_PASS", total == 0 && full == 0,
         "benign seeds 1..9, %llu events through real core: findings per seed [%s], total %llu "
         "(code 11: %llu, code 12: %llu; sequences strictly increasing per stream: %s); ingest rc FULL %llu",
         (unsigned long long)events, per_seed, (unsigned long long)total, (unsigned long long)by[11],
         (unsigned long long)by[12], incr_all ? "yes" : "NO", (unsigned long long)full);
}

/* ======================================================================= */
/* ARGUS_MEMORY                                                            */
/* ======================================================================= */
static int allowed_import(const char *s)
{
    static const char *prefix[] = { "argus_", "sha256_", "__aarch64_", "__stack_chk_", "__memcpy_chk",
                                    "__memset_chk", "__memmove_chk" };
    static const char *exact[] = { "memset", "memcpy", "memcmp", "memmove", "bzero", "__bzero" };
    for (size_t i = 0; i < sizeof prefix / sizeof *prefix; i++)
        if (strncmp(s, prefix[i], strlen(prefix[i])) == 0) return 1;
    for (size_t i = 0; i < sizeof exact / sizeof *exact; i++)
        if (strcmp(s, exact[i]) == 0) return 1;
    return 0;
}

static void gate_memory(int nobj, char **objs)
{
    size_t core_fp = argus_core_footprint();
    size_t ring_fp = argus_ring_footprint(RING_CAP);
    int bad = 0, checked = 0, nm_err = 0;
    char imports[1024] = "";
    size_t ioff = 0;
    for (int i = 0; i < nobj; i++) {
        char cmd[1200];
        snprintf(cmd, sizeof cmd, "nm -u '%s' 2>/dev/null", objs[i]);
        FILE *p = popen(cmd, "r");
        if (!p) { nm_err++; continue; }
        char line[512];
        while (fgets(line, sizeof line, p)) {
            line[strcspn(line, "\r\n")] = 0;
            char *sym = strrchr(line, ' ');
            sym = sym ? sym + 1 : line;
            if (!*sym || strchr(sym, ':')) continue;
            const char *s = sym;
#ifdef __APPLE__
            if (*s == '_') s++;
#endif
            if (!allowed_import(s)) {
                bad++;
                printf("  forbidden import in %s: %s\n", objs[i], s);
            }
            char key[520];
            snprintf(key, sizeof key, " %.500s ", s);
            char probe[1100];
            snprintf(probe, sizeof probe, " %s ", imports);
            if (!strstr(probe, key) && ioff + strlen(s) + 2 < sizeof imports)
                ioff = snprintf_advance(ioff, sizeof imports, snprintf(imports + ioff, sizeof imports - ioff, "%s%s", ioff ? " " : "", s));
        }
        if (pclose(p) != 0) nm_err++;
        checked++;
    }
    gate("ARGUS_MEMORY", nobj >= 4 && checked == nobj && nm_err == 0 && bad == 0 && core_fp > 0 && ring_fp > 0,
         "argus_core_footprint %zu B; ring(%u) footprint %zu B (%zu B/event slot); %d objects checked with nm -u, "
         "forbidden imports %d (allowed: argus_/sha256_ cross-calls, mem*, stack protector, aarch64 outline atomics); "
         "imports seen: %s",
         core_fp, RING_CAP, ring_fp, sizeof(ArgusEvent), checked, bad, imports[0] ? imports : "(none)");
}

/* ======================================================================= */
/* ingest timing: benign corpus through the real core, real SHA-256          */
/* ======================================================================= */
static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

static void ingest_timing(unsigned reps)
{
    size_t total = (size_t)reps * n_benign;
    uint64_t *ns = xalloc(total * sizeof *ns);
    uint64_t *ov = xalloc(10000 * sizeof *ov);
    for (int i = 0; i < 10000; i++) { uint64_t a = now_ns(), b = now_ns(); ov[i] = b - a; }
    qsort(ov, 10000, sizeof *ov, cmp_u64);
    size_t k = 0;
    ArgusFinding out[FCAP];
    for (unsigned r = 0; r < reps; r++) {
        void *mem = xalloc(argus_core_footprint());
        ArgusCore *core;
        argus_core_init(&core, mem, argus_core_footprint());
        for (size_t i = 0; i < n_benign; i++) {
            size_t n;
            uint64_t a = now_ns();
            argus_core_ingest(core, &benign[i], out, FCAP, &n);
            ns[k++] = now_ns() - a;
        }
        free(mem);
    }
    /* whole-stream pass without per-event timers, for a clean mean */
    uint64_t clean_ns = 0;
    for (unsigned r = 0; r < reps; r++) {
        void *mem = xalloc(argus_core_footprint());
        ArgusCore *core;
        argus_core_init(&core, mem, argus_core_footprint());
        uint64_t b0 = now_ns();
        for (size_t i = 0; i < n_benign; i++) { size_t n; argus_core_ingest(core, &benign[i], out, FCAP, &n); }
        clean_ns += now_ns() - b0;
        free(mem);
    }
    qsort(ns, total, sizeof *ns, cmp_u64);
    printf("INGEST ns/event (benign seed 1, %zu events x %u fresh cores, real core + detectors + SHA-256): "
           "p50 %llu p99 %llu p99.9 %llu max %llu; mean without per-event timers %.1f; timer overhead p50 %llu ns "
           "(included in p50/p99)\n",
           n_benign, reps, (unsigned long long)ns[total / 2], (unsigned long long)ns[(total * 99) / 100],
           (unsigned long long)ns[(total * 999) / 1000], (unsigned long long)ns[total - 1],
           (double)clean_ns / (double)total, (unsigned long long)ov[5000]);
    free(ns);
    free(ov);
}

/* capacity probe: does the hostile corpus at N_PROBE overflow the core's tables? */
static void capacity_probe(void)
{
    static ArgusEvent big[N_PROBE];
    static ArgusExpectedFinding bexp[N_PROBE];
    size_t ne = 0;
    size_t n = argus_corpus_hostile(big, N_PROBE, 1, bexp, N_PROBE, &ne);
    Run r;
    run_init(&r, (size_t)N_PROBE * FCAP);
    uint64_t first_full = 0;
    for (size_t i = 0; i < n; i++) {
        uint64_t before = r.rc_full;
        run_ingest(&r, &big[i]);
        if (r.rc_full != before && !first_full) first_full = big[i].sequence;
    }
    printf("NOTE capacity probe (not a gate): hostile seed 1 at %zu events, %zu injected: findings %zu, "
           "code 11 %llu, code 12 %llu, ingest rc FULL %llu (first at seq %llu)\n",
           n, ne, r.nf, (unsigned long long)r.per_code[11], (unsigned long long)r.per_code[12],
           (unsigned long long)r.rc_full, (unsigned long long)first_full);
    run_free(&r);
}

int main(int argc, char **argv)
{
    int bench = 0;
    int nobj = 0;
    char **objs = xalloc((size_t)(argc + 1) * sizeof *objs);
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--bench") == 0) bench = 1;
        else objs[nobj++] = argv[i];
    }
    n_benign = argus_corpus_benign(benign, N_CORPUS, 1);
    n_hostile = argus_corpus_hostile(hostile, N_CORPUS, 1, expect, N_CORPUS, &n_expect);
    if (n_benign != N_CORPUS || n_hostile != N_CORPUS || n_expect == 0) {
        fprintf(stderr, "corpus generation failed (%zu %zu %zu)\n", n_benign, n_hostile, n_expect);
        return 2;
    }
    if (bench) {
        ingest_timing(200);
        free(objs);
        return 0;
    }

    run_init(&direct_h, (size_t)N_CORPUS * FCAP);
    for (size_t i = 0; i < n_hostile; i++) run_ingest(&direct_h, &hostile[i]);

    gate_abi();
    gate_secret();
    gate_transport();
    gate_saturation();
    gate_determinism();
    gate_hard_invariants();
    gate_false_positive();
    gate_memory(nobj, objs);
    ingest_timing(20);
    capacity_probe();

    run_free(&direct_h);
    run_free(&ring_h);
    run_free(&burst_h);
    free(objs);
    printf("test_argus_integration: %s (%d gate(s) failed)\n", gates_failed ? "FAIL" : "PASS", gates_failed);
    return gates_failed ? 1 : 0;
}
