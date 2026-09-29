/*
 * test_argus_determinism.c -- lane D determinism gate + provisional ingest
 * microbenchmark.
 *
 * A 10,000-event synthetic stream (xorshift64*, fixed seed, covers every event
 * kind, non-OK outcomes, sequence repeats, malformed events, table overflow)
 * (cap_id up to 260, so ids >= ARGUS_CAP_MAX exercise the malformed path; replays and
 * stale grants/revokes exercise AUTHORITY_REPLAY and not-applied) is fed to two fresh cores in lockstep: return codes and finding bytes must be
 * identical per event, and final state digests and chains equal. The same
 * stream is then fed with two other chunkings (one event at a time with
 * digest/health queries interleaved; and split at event 3333 with the core's
 * memory byte-copied to a different buffer), plus once with a 1-finding output
 * buffer, and all must reach the same state digest.
 *
 * Timing numbers use the STUB hash (FNV), not SHA-256: provisional, Mac only.
 *
 * v1.2 (ARGUS-1): after the ARGUS-0 part (unchanged, same stream, same output
 * lines), argus1_containment_determinism() replays recorded containment fixtures
 * (kinds 90-93, one per code 17-21 plus a happy path; see the fixture block) and
 * the ARGUS-0 stream + all fixtures, with known-answer digests (stub hash).
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
    50, 51, 52, 60, 61, 62, 63, 70, 71, 72, 80, 81
};
#define N_STREAMS 3u   /* v1.1: stream ids per machine */
#define N_STORES 12u   /* v1.1: World stores; more than ARGUS_WORLD_STORES so the table fills */
#define N_KINDS (sizeof kinds / sizeof kinds[0])

static void gen(void)
{
    static uint64_t seqs[N_MACH][N_STREAMS][2];
    static uint64_t world[N_STORES];
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
        uint32_t st = rn(N_STREAMS);
        e->flags = (uint16_t)(ARGUS_FLAG_SYNTHETIC | (cons ? ARGUS_FLAG_CONSUMER : 0) | (st << ARGUS_FLAG_STREAM_SHIFT));
        uint64_t *sq = &seqs[m][st][cons];
        uint32_t r = rn(100);
        if (r == 0 && *sq > 0)
            e->sequence = *sq;                          /* replay */
        else if (r == 1 && *sq > 1)
            e->sequence = *sq - 1;                      /* reorder */
        else
            e->sequence = ++*sq;
        e->tick = i;
        e->principal = 1 + rn(12);
        e->code = (int32_t)rn(3) - 1;
        e->cap_id = rn(50) == 0 ? ARGUS_CAP_NONE : rn(261);
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
        case ARGUS_EV_WORLD_COMMITTED: {
            uint32_t s = rn(10) < 8 ? rn(3) : rn(N_STORES);
            world[s] = rn(10) == 0 && world[s] > 2 ? world[s] - 2 : world[s] + 1;
            e->object_id = s;
            e->world_generation = world[s]; dg(e->evidence_digest, 5000 + 100 * s + (uint32_t)world[s]); break;
        }
        case ARGUS_EV_CAPABILITY_USE_SUMMARY: e->resource = 1 + rn(4096); e->world_generation = e->cap_generation - (e->cap_generation ? rn(2) : 0); break;
        case ARGUS_EV_POLICY_CHANGED: case ARGUS_EV_RUNTIME_BUILD_CHANGED: dg(e->evidence_digest, 7000 + rn(5)); break;
        case ARGUS_EV_TELEMETRY_DROPPED: e->object_id = 1 + rn(4); e->resource = 1 + rn(50); break;
        default: break;
        }
        if (rn(100) == 0)
            e->version = 0;                             /* malformed */
    }
}

typedef struct {
    uint64_t fold, nfind, rc_fold, full, overflow, malformed, seq_anom, det_findings, replay, malformed_f;
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
        if (f[i].code == ARGUS_F_AUTHORITY_REPLAY) s->replay++;
        if (f[i].code == ARGUS_F_MALFORMED_EVENT) s->malformed_f++;
        if (f[i].code != ARGUS_F_SEQUENCE_ANOMALY && f[i].code != ARGUS_F_TELEMETRY_LOSS &&
            f[i].code != ARGUS_F_AUTHORITY_REPLAY && f[i].code != ARGUS_F_MALFORMED_EVENT) s->det_findings++;
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

/* ======================================================================== *
 * ARGUS-1 (v1.2) containment fixtures, lane D.  RECORDED FOR REUSE by lanes
 * C (argus_contain unit tests), H (hostile) and X (bridge e2e): each fixture is
 * the event pattern spec section 3/4.1 says argus_contain must turn into the
 * listed code (fx_expect[]). The core itself raises none of 17-21: it only
 * validates, sequence-checks, counts and chains 90-93, applies no shadow
 * change for them and never runs a detector on them (spec section 3, lane D).
 *
 * Encoding per spec section 3 so the streams also pass lane B's real v1.2
 * validate: version 1, class CRITICAL, effect NONE, object_id =
 * ARGUS_CONTAIN_PACK(type, status, finding_code), outcome paired with status,
 * world_generation = request_id (!= 0), CONSUMER only on 90, resource =
 * finding_sequence (90) / decision_id (91) / slots revoked (92).
 *
 * Fixture k uses machine 200+k (authority stream 0, bridge stream 1, Omega
 * stream 2, consumer stream 0 + CONSUMER), caps 200+2k / 201+2k, principal
 * 100+k, so all fixtures can be concatenated into one coherent stream.
 * The trigger (event 2) is a stale-generation USED: the stub detector raises
 * code 2 STALE_GENERATION HIGH (the ARGUS-1 LIVE RevokeCapability trigger).
 *
 * fx_request_digest is a TEST-ONLY stand-in (152-byte canonical encoding per
 * spec section 2, folded with the stub FNV-style hash); replace it with lane B's
 * argus_contain_request_digest (SHA-256) when argus_event.c lands. Known-answer
 * digests below are under the lane-D STUB hash, not SHA-256; the SHA-256 pins
 * belong in L0's integration test once lane B merges.
 * ======================================================================== */

enum { FX_HAPPY = 0, FX_C17, FX_C18, FX_C19, FX_C20, FX_C21, FX_COUNT };
static const char *const fx_name[FX_COUNT] = {
    "happy: 90 -> 91 GRANT -> one kind 4 -> 92 DONE (+93)",
    "code17: 91 GRANT for an unknown request_id",
    "code18: 92 DONE while the request is only PROPOSED",
    "code19: 91 GRANT -> 92 DONE with no kind 4",
    "code20: 91 ESCALATE then no next step for TIMEOUT_EVENTS+1 events",
    "code21: 91 GRANT -> two kind 4 (cascade) -> 92 FAILED_SCOPE low32=2",
};
/* Code argus_contain must raise for the fixture (0 = none) and the index of the
 * event on which it is due (code 20: the last event, once the timeout elapsed). */
static const uint16_t fx_expect[FX_COUNT] = { 0, 17, 18, 19, 20, 21 };
static size_t fx_trigger[FX_COUNT];

#define FX_MAX (ARGUS_CONTAIN_TIMEOUT_EVENTS + 64u)
static ArgusEvent fx_ev[FX_COUNT][FX_MAX];
static size_t fx_n[FX_COUNT];
static ArgusContainmentRequest fx_req[FX_COUNT];

static void fx_put(uint8_t *p, uint64_t v, int n) { for (int i = 0; i < n; i++) p[i] = (uint8_t)(v >> (8 * i)); }

/* TEST-ONLY canonical 152-byte encoding (spec section 2 offsets), to be replaced by lane B's encoder. */
static void fx_request_encode(const ArgusContainmentRequest *r, uint8_t b[ARGUS_CONTAIN_REQUEST_SIZE])
{
    memset(b, 0, ARGUS_CONTAIN_REQUEST_SIZE);
    fx_put(b + 0, r->incident_id, 8); b[8] = r->containment; b[9] = r->severity;
    fx_put(b + 10, r->finding_code, 2); fx_put(b + 12, r->principal, 4);
    fx_put(b + 16, r->target.cap_id, 4); fx_put(b + 20, r->target.generation, 8);
    memcpy(b + 28, r->machine_id, ARGUS_MACHINE_ID_LEN); memcpy(b + 60, r->finding_digest, ARGUS_DIGEST_LEN);
    fx_put(b + 92, r->request_id, 8); fx_put(b + 100, r->finding_sequence, 8);
    fx_put(b + 108, r->target_object, 4); fx_put(b + 112, r->target_rights, 4);
    memcpy(b + 116, r->target_digest, ARGUS_DIGEST_LEN);
    fx_put(b + 148, r->flags, 2); b[150] = r->version; b[151] = r->reserved;
}

/* TEST-ONLY digest stand-in (not SHA-256). */
static void fx_request_digest(const ArgusContainmentRequest *r, uint8_t out[ARGUS_DIGEST_LEN])
{
    uint8_t b[ARGUS_CONTAIN_REQUEST_SIZE];
    fx_request_encode(r, b);
    for (int lane = 0; lane < 4; lane++) {
        uint64_t h = 0xcbf29ce484222325ull ^ ((uint64_t)(lane + 7) * 0x9e3779b97f4a7c15ull);
        for (size_t i = 0; i < sizeof b; i++) { h ^= b[i]; h *= 0x100000001b3ull; }
        fx_put(out + 8 * lane, h, 8);
    }
}

static ArgusEvent fx_base(uint16_t kind, uint32_t k, uint16_t stream, uint64_t seq)
{
    ArgusEvent e = ev_make(kind, seq);
    mid(e.machine_id, 200u + k);
    e.flags = (uint16_t)(ARGUS_FLAG_SYNTHETIC | (stream << ARGUS_FLAG_STREAM_SHIFT));
    return e;
}

/* 90-92 record for fixture k's request (spec section 3 field table). */
static ArgusEvent fx_contain(uint16_t kind, uint32_t k, uint64_t seq, uint8_t status, uint8_t outcome,
                             uint64_t request_id, uint64_t resource, int32_t code, uint64_t tick)
{
    const ArgusContainmentRequest *r = &fx_req[k];
    ArgusEvent e = fx_base(kind, k, kind == ARGUS_EV_CONTAINMENT_PROPOSED ? 0 : 1, seq);
    e.flags = kind == ARGUS_EV_CONTAINMENT_PROPOSED ? ARGUS_FLAG_CONSUMER
                                                    : (uint16_t)(1u << ARGUS_FLAG_STREAM_SHIFT);
    e.class_ = ARGUS_CLASS_CRITICAL;
    e.effect_class = ARGUS_EFFECT_NONE;
    e.outcome = outcome;
    e.code = code;
    e.principal = r->principal;
    e.cap_id = r->target.cap_id;
    e.cap_generation = r->target.generation;
    e.object_id = ARGUS_CONTAIN_PACK(r->containment, status, r->finding_code);
    e.world_generation = request_id;
    e.resource = resource;
    e.tick = tick;
    memcpy(e.machine_id, r->machine_id, ARGUS_MACHINE_ID_LEN);
    fx_request_digest(r, e.evidence_digest);
    return e;
}

/* Builds fixture k while ingesting it into a scratch core, so the request's
 * finding_digest / incident_id come from the finding the core really emitted. */
static void fx_build(uint32_t k, ArgusCore *c)
{
    ArgusEvent *s = fx_ev[k];
    size_t n = 0;
    uint32_t cap = 200u + 2u * k, child = cap + 1u, P = 100u + k;
    ArgusFinding f[ARGUS_CORE_MAX_FINDINGS];
    size_t nf;
    stub_detect_mode = 0;

    ArgusEvent e = fx_base(ARGUS_EV_CAPABILITY_GRANTED, k, 0, 1);
    e.principal = P; e.cap_id = cap; e.cap_generation = 3; e.object_id = 0x1; e.resource = 0x77;
    s[n++] = e;
    e = fx_base(ARGUS_EV_CAPABILITY_GRANTED, k, 0, 2);       /* a descendant, used by the cascade fixture */
    e.principal = P; e.cap_id = child; e.cap_generation = 1; e.object_id = 0x1; e.resource = 0x77;
    s[n++] = e;
    e = fx_base(ARGUS_EV_CAPABILITY_USED, k, 0, 3);          /* stale generation -> code 2 HIGH (stub) */
    e.principal = P; e.cap_id = cap; e.cap_generation = 2;
    s[n++] = e;
    for (size_t i = 0; i < n; i++)
        argus_core_ingest(c, &s[i], f, ARGUS_CORE_MAX_FINDINGS, &nf);
    CHECK(nf == 1 && f[0].code == ARGUS_F_STALE_GENERATION && f[0].sequence == 3);

    ArgusContainmentRequest *r = &fx_req[k];
    memset(r, 0, sizeof *r);
    uint64_t first = 0;
    CHECK(argus_core_incident(c, P, ARGUS_F_STALE_GENERATION, &first) == ARGUS_OK && first == 3);
    r->incident_id = first;
    r->containment = ARGUS_CONTAIN_REVOKE_CAPABILITY;
    r->severity = f[0].severity;
    r->finding_code = f[0].code;
    r->principal = P;
    r->target.cap_id = cap;
    r->target.generation = 3;                              /* ARGUS shadow generation (I1.d) */
    memcpy(r->machine_id, f[0].machine_id, ARGUS_MACHINE_ID_LEN);
    argus_finding_digest(&f[0], r->finding_digest);
    r->request_id = 1;
    r->finding_sequence = f[0].sequence;
    r->version = ARGUS_CONTAIN_REQUEST_VERSION;

    size_t first_tail = n;
    s[n++] = fx_contain(ARGUS_EV_CONTAINMENT_PROPOSED, k, 1, ARGUS_CSTATUS_PROPOSED, ARGUS_OUTCOME_OK, 1,
                        r->finding_sequence, 0, 0);
    uint64_t bs = 1;                                       /* bridge stream sequence */
    ArgusEvent rv;
    switch (k) {
    case FX_HAPPY:
        s[n++] = fx_contain(ARGUS_EV_CONTAINMENT_DECIDED, k, bs++, ARGUS_CSTATUS_GRANT, ARGUS_OUTCOME_OK, 1, 1, 0, 10);
        rv = fx_base(ARGUS_EV_CAPABILITY_REVOKED, k, 1, bs++);
        rv.flags = (uint16_t)(1u << ARGUS_FLAG_STREAM_SHIFT);
        rv.principal = P; rv.cap_id = cap; rv.cap_generation = 3; rv.tick = 11;
        s[n++] = rv;
        s[n++] = fx_contain(ARGUS_EV_CONTAINMENT_EXECUTED, k, bs++, ARGUS_CSTATUS_DONE, ARGUS_OUTCOME_OK, 1, 1, 0, 12);
        e = fx_base(ARGUS_EV_AUTHORITY_ESCALATED, k, 2, 1);
        e.flags = (uint16_t)(2u << ARGUS_FLAG_STREAM_SHIFT);
        e.class_ = ARGUS_CLASS_CRITICAL; e.effect_class = ARGUS_EFFECT_NONE;
        e.principal = P; e.cap_id = cap; e.cap_generation = 3; e.code = 7; e.resource = 0x77; e.tick = 13;
        s[n++] = e;
        fx_trigger[k] = 0;
        break;
    case FX_C17:
        fx_trigger[k] = n;
        s[n++] = fx_contain(ARGUS_EV_CONTAINMENT_DECIDED, k, bs++, ARGUS_CSTATUS_GRANT, ARGUS_OUTCOME_OK, 99, 1, 0, 10);
        break;
    case FX_C18:
        fx_trigger[k] = n;
        s[n++] = fx_contain(ARGUS_EV_CONTAINMENT_EXECUTED, k, bs++, ARGUS_CSTATUS_DONE, ARGUS_OUTCOME_OK, 1, 1, 0, 10);
        break;
    case FX_C19:
        s[n++] = fx_contain(ARGUS_EV_CONTAINMENT_DECIDED, k, bs++, ARGUS_CSTATUS_GRANT, ARGUS_OUTCOME_OK, 1, 1, 0, 10);
        fx_trigger[k] = n;
        s[n++] = fx_contain(ARGUS_EV_CONTAINMENT_EXECUTED, k, bs++, ARGUS_CSTATUS_DONE, ARGUS_OUTCOME_OK, 1, 1, 0, 11);
        break;
    case FX_C20:
        s[n++] = fx_contain(ARGUS_EV_CONTAINMENT_DECIDED, k, bs++, ARGUS_CSTATUS_ESCALATE, ARGUS_OUTCOME_ERROR, 1, 1,
                            1114, 10);
        for (uint32_t i = 0; i <= ARGUS_CONTAIN_TIMEOUT_EVENTS; i++) {   /* benign: valid use of the live cap */
            e = fx_base(ARGUS_EV_CAPABILITY_USED, k, 0, 4u + i);
            e.principal = P; e.cap_id = cap; e.cap_generation = 3; e.tick = 11u + i;
            s[n++] = e;
        }
        fx_trigger[k] = n - 1;
        break;
    case FX_C21:
        s[n++] = fx_contain(ARGUS_EV_CONTAINMENT_DECIDED, k, bs++, ARGUS_CSTATUS_GRANT, ARGUS_OUTCOME_OK, 1, 1, 0, 10);
        rv = fx_base(ARGUS_EV_CAPABILITY_REVOKED, k, 1, bs++);
        rv.flags = (uint16_t)(1u << ARGUS_FLAG_STREAM_SHIFT);
        rv.principal = P; rv.cap_id = cap; rv.cap_generation = 3; rv.tick = 11;
        s[n++] = rv;
        rv.sequence = bs++; rv.cap_id = child; rv.cap_generation = 1; rv.tick = 11;
        fx_trigger[k] = n;                                 /* the second kind 4 */
        s[n++] = rv;
        s[n++] = fx_contain(ARGUS_EV_CONTAINMENT_EXECUTED, k, bs++, ARGUS_CSTATUS_FAILED_SCOPE, ARGUS_OUTCOME_ERROR, 1,
                            2, 0, 12);
        break;
    default:
        break;
    }
    for (size_t i = first_tail; i < n; i++)
        argus_core_ingest(c, &s[i], f, ARGUS_CORE_MAX_FINDINGS, &nf);
    fx_n[k] = n;
}

typedef struct { uint8_t chain[32], state[32]; uint64_t ffold, nfind, rcfold, contain_events, contain_findings, det_calls_on_contain, codes_17_21; } FxRun;

static int fx_is_contain(uint16_t kind) { return kind >= ARGUS_EV_CONTAINMENT_PROPOSED && kind <= ARGUS_EV_AUTHORITY_ESCALATED; }

/* Replays s[0..n) into a fresh core at mem, byte-copying the core to mem2 (and back) at
 * every `chunk` boundary (0 = no copies). */
static void fx_replay(const ArgusEvent *s, size_t n, uint8_t *m1, uint8_t *m2, size_t chunk, FxRun *o)
{
    ArgusCore *c = NULL;
    uint8_t *cur = m1, *other = m2;
    memset(o, 0, sizeof *o);
    o->ffold = o->rcfold = 0xcbf29ce484222325ull;
    stub_detect_mode = 0;
    CHECK(argus_core_init(&c, cur, 1 << 17) == ARGUS_OK);
    static ArgusFinding f[ARGUS_CORE_MAX_FINDINGS];
    for (size_t i = 0; i < n; i++) {
        if (chunk && i && i % chunk == 0) {
            memcpy(other, cur, argus_core_footprint());
            memset(cur, 0xEE, argus_core_footprint());
            uint8_t *t = cur; cur = other; other = t;
            c = (ArgusCore *)(void *)cur;
        }
        size_t nf = 0;
        uint64_t calls = stub_detect_calls;
        int rc = argus_core_ingest(c, &s[i], f, ARGUS_CORE_MAX_FINDINGS, &nf);
        int32_t r = rc;
        fold_bytes(&o->rcfold, &r, sizeof r);
        fold_bytes(&o->ffold, f, nf * sizeof f[0]);
        o->nfind += nf;
        for (size_t j = 0; j < nf; j++)
            o->codes_17_21 += f[j].code >= ARGUS_F_CONTAINMENT_DECISION_UNMATCHED;   /* core never raises 17-21 */
        if (fx_is_contain(s[i].kind)) {
            o->contain_events++;
            o->contain_findings += nf;
            o->det_calls_on_contain += stub_detect_calls - calls;
        }
    }
    ArgusCoreHealth h;
    argus_core_state_digest(c, o->state);
    argus_core_health(c, &h);
    memcpy(o->chain, h.chain, 32);
}

static int fx_same(const FxRun *a, const FxRun *b)
{
    return !memcmp(a->chain, b->chain, 32) && !memcmp(a->state, b->state, 32) && a->ffold == b->ffold &&
           a->nfind == b->nfind && a->rcfold == b->rcfold;
}

static uint64_t fx_head(const uint8_t d[32])
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | d[i];
    return v;
}

/* Known answers (lane-D STUB hash, first 8 bytes of chain / state digest). */
static const uint64_t fx_ka_chain[FX_COUNT] = {
    0xc2b624ed62918752ull, 0x3a019b7017a89eccull, 0x5c7292fc11c74dd6ull,
    0x414d5d2d901c778aull, 0x2c7b1d0e36873807ull, 0xe7c88ea0e59cf4f2ull };
static const uint64_t fx_ka_state[FX_COUNT] = {
    0x47aa8681a74ca412ull, 0xe24af450450af397ull, 0xd23ec461962d79b8ull,
    0x55e19d566fc41b17ull, 0xf8586b5451a5bde7ull, 0x826a85dbc56b0b7full };

static ArgusEvent fx_all[N_EVENTS + FX_COUNT * FX_MAX];

static void argus1_containment_determinism(void)
{
    static _Alignas(16) uint8_t m1[1 << 17], m2[1 << 17];
    ArgusCore *c = NULL;
    int ka_ok = 1;
    for (uint32_t k = 0; k < FX_COUNT; k++) {
        CHECK(argus_core_init(&c, m1, sizeof m1) == ARGUS_OK);
        fx_build(k, c);
        ArgusCoreHealth hb; argus_core_health(c, &hb);
        uint8_t sb[32]; argus_core_state_digest(c, sb);
        FxRun a, b, d;
        fx_replay(fx_ev[k], fx_n[k], m1, m2, 0, &a);
        fx_replay(fx_ev[k], fx_n[k], m1, m2, 0, &b);
        fx_replay(fx_ev[k], fx_n[k], m1, m2, 2, &d);          /* byte-copy every 2 events */
        CHECK(fx_same(&a, &b) && fx_same(&a, &d));
        CHECK(!memcmp(a.chain, hb.chain, 32) && !memcmp(a.state, sb, 32));   /* build run == replays */
        CHECK(a.contain_events > 0 && a.contain_findings == 0 && a.det_calls_on_contain == 0 && a.codes_17_21 == 0);
        CHECK(hb.events_received == fx_n[k] && hb.events_rejected == 0);
        CHECK(fx_expect[k] == 0 || fx_trigger[k] < fx_n[k]);
        int ok = fx_head(a.chain) == fx_ka_chain[k] && fx_head(a.state) == fx_ka_state[k];
        ka_ok &= ok;
        printf("argus1 fixture %u [%s]: %zu events (%llu of kinds 90-93, 0 core findings on them), expects code %u "
               "at event %zu; chain %016llx state %016llx (stub hash) known-answer %s\n",
               k, fx_name[k], fx_n[k], (unsigned long long)a.contain_events, fx_expect[k], fx_trigger[k],
               (unsigned long long)fx_head(a.chain), (unsigned long long)fx_head(a.state), ok ? "OK" : "MISMATCH");
    }
    CHECK(ka_ok);

    /* Cap-shadow effect of the happy path: 90-93 change nothing, the kind 4 revokes exactly as ARGUS-0. */
    CHECK(argus_core_init(&c, m1, sizeof m1) == ARGUS_OK);
    ArgusCapShadow before, after;
    ArgusFinding f[ARGUS_CORE_MAX_FINDINGS]; size_t nf;
    for (size_t i = 0; i < fx_n[FX_HAPPY]; i++) {
        const ArgusEvent *e = &fx_ev[FX_HAPPY][i];
        argus_core_ops()->cap(argus_core_view(c), 200, &before);
        argus_core_ingest(c, e, f, ARGUS_CORE_MAX_FINDINGS, &nf);
        argus_core_ops()->cap(argus_core_view(c), 200, &after);
        if (fx_is_contain(e->kind))
            CHECK(!memcmp(&before, &after, sizeof before) && nf == 0);
        if (e->kind == ARGUS_EV_CAPABILITY_REVOKED)
            CHECK(before.state == ARGUS_SHADOW_LIVE && after.state == ARGUS_SHADOW_REVOKED &&
                  after.revoked_sequence == e->sequence && nf == 0);
    }

    /* Mixed stream: the ARGUS-0 10,000-event stream followed by every fixture, replayed twice
     * and with byte-copies at 1/7/64/4096-event chunk boundaries: identical everywhere. */
    size_t n = 0;
    memcpy(fx_all, stream, sizeof stream); n = N_EVENTS;
    for (uint32_t k = 0; k < FX_COUNT; k++) { memcpy(&fx_all[n], fx_ev[k], fx_n[k] * sizeof fx_all[0]); n += fx_n[k]; }
    FxRun r0, r1;
    fx_replay(fx_all, n, m1, m2, 0, &r0);
    fx_replay(fx_all, n, m1, m2, 0, &r1);
    CHECK(fx_same(&r0, &r1));
    static const size_t chunks[] = { 1, 7, 64, 4096 };
    int chunk_ok = 1;
    for (size_t i = 0; i < sizeof chunks / sizeof chunks[0]; i++) {
        FxRun rc; fx_replay(fx_all, n, m1, m2, chunks[i], &rc);
        chunk_ok &= fx_same(&r0, &rc);
    }
    CHECK(chunk_ok);
    CHECK(r0.contain_findings == 0 && r0.det_calls_on_contain == 0 && r0.codes_17_21 == 0);
    int mixed_ok = fx_head(r0.chain) == 0x9380e0f276189543ull && fx_head(r0.state) == 0xc351c431495e9bdeull;
    CHECK(mixed_ok);
    printf("argus1 mixed stream: %zu events (%llu of kinds 90-93), replayed twice + chunks 1/7/64/4096 %s; "
           "chain %016llx state %016llx (stub hash) known-answer %s\n",
           n, (unsigned long long)r0.contain_events, chunk_ok ? "identical" : "DIFFER",
           (unsigned long long)fx_head(r0.chain), (unsigned long long)fx_head(r0.state), mixed_ok ? "OK" : "MISMATCH");
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
    int seen[ARGUS_EV_KIND_MAX + 1] = {0};   /* was [81]: kind 81 wrote out of bounds (UBSan) */
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
    CHECK(sa.replay > 0 && sa.malformed_f == sa.malformed);   /* every MALFORMED return carries one code-16 finding */
    ArgusCoreHealth h1; argus_core_health(A, &h1);
    CHECK(h1.events_not_applied > 0 && h1.events_rejected == sa.malformed && h1.tables_full == sa.full);

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
            argus_core_ops()->world(argus_core_view(C), i % N_STORES, &w);
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
    CHECK(ha.events_not_applied == he.events_not_applied && ha.incidents_untracked == he.incidents_untracked &&
          ha.producers_untracked == he.producers_untracked && ha.tables_full == he.tables_full);

    printf("determinism: %u events, %llu findings (%llu sequence, %llu replay, %llu malformed, %llu detector), %llu FULL, "
           "%llu MALFORMED returns, %llu not applied, incidents %llu\n",
           N_EVENTS, (unsigned long long)sa.nfind, (unsigned long long)sa.seq_anom, (unsigned long long)sa.replay,
           (unsigned long long)sa.malformed_f, (unsigned long long)sa.det_findings, (unsigned long long)sa.full,
           (unsigned long long)sa.malformed, (unsigned long long)ha.events_not_applied, (unsigned long long)ha.incidents_open);
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

    /* v1.2 (ARGUS-1 lane D): containment fixtures + mixed-stream replay. */
    argus1_containment_determinism();

    printf("test_argus_determinism: %d passed, %d failed\n", t_pass, t_fail);
    return t_fail ? 1 : 0;
}
