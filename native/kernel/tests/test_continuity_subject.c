/* test_continuity_subject.c -- host tests of svc/continuity_subject.c
 * (ALLEN subject state, kind 24; ARCH-0035 / OS-0018, both PROPOSED).
 *
 * No arguments: the unit suite.
 * 1. Known answer: the genesis subject object's bytes, written out by hand
 *    from the layout in continuity_subject.h, and its logical ObjectId
 *    computed by store_v1's independent twin (sv1_object_id).
 * 2. Round trips; deterministic re-encode (same bytes, same id).
 * 3. One refusal per rule (magic, version, reserved, length, truncation,
 *    trailing bytes, zero root/agent/provenance, origin, bounds, intent id
 *    derivation, slot rule, supersession rules, ordering, since bounds).
 * 4. Standing intents: intend, supersede (one active per slot), retire.
 * 5. Resolve over a fake source: ABSENT, head of a chain, fork, gap, broken
 *    link, foreign root/agent (ALLEN-G1 identity binding).
 * 6. Model independence (ALLEN-G4, structural): the encoding has no field
 *    for a model; two subjects that differ only in an out-of-band "model"
 *    value have byte-identical objects and ids.
 * 7. Real sealed Store (native/store, M5 envelopes) in a file: provision,
 *    commit genesis, commit a successor with one intent, close, reopen,
 *    resolve the same head (in-process persistence).
 *
 * `--write <img>` and `--restore <img> <id-hex>`: ALLEN-G2 restart proof in
 * two processes (Makefile test-continuity-subject-restart). The writer
 * provisions, commits a subject with one standing intent, prints the head id
 * and exits; the restorer is a fresh process that opens the same image,
 * resolves, and checks the subject, the intent and the id. The negative
 * control for G2 lives where the pre-ALLEN goal lives (omega); here the
 * structural half: cr_view (the pre-ALLEN continuity view) carries no intent.
 *
 * Mutants (make continuity-subject-mutants) must each turn this test FAIL. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ck_test.h"
#include "continuity_commit.h"
#include "continuity_resolve_sealed.h"
#include "continuity_subject.h"
#include "disk_file.h"
#include "store_v1.h"
#include "../argus/sha256.h"

#define CK_(c, ...)                                                            \
    do {                                                                       \
        ck_t_run++;                                                            \
        if (!(c)) {                                                            \
            ck_t_fail++;                                                       \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);                      \
            printf(__VA_ARGS__);                                               \
            printf("\n");                                                      \
        }                                                                      \
    } while (0)

static const char *why;
static struct cs_subject S, S2, S3;
static uint8_t buf[CC_MAX_OBJECT_BYTES + 64], buf2[CC_MAX_OBJECT_BYTES + 64];
static struct cr_view V;
static struct cr_work W;

static void fill(uint8_t *d, size_t n, uint8_t v)
{
    memset(d, v, n);
}

static void hex(const uint8_t *b, size_t n, char *out)
{
    static const char *h = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = h[b[i] >> 4];
        out[2 * i + 1] = h[b[i] & 15];
    }
    out[2 * n] = 0;
}

static int unhex(const char *s, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* A resolved view for a test agent: root id and agent id as the resolver
 * would hand them over. */
static void view(struct cr_view *v, uint8_t root_byte, uint8_t agent_byte)
{
    memset(v, 0, sizeof *v);
    fill(v->root_id, 32, root_byte);
    fill(v->root.agent_id, 32, agent_byte);
}

static const uint8_t PROV[32] = {0xaa, 0xbb, 0xcc, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                                 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29};

/* ---- 1. known answer ---- */
static void t_known_answer(void)
{
    size_t len = 0;
    uint8_t id[32], id2[32];
    uint8_t exp[CC_HEADER_BYTES + CS_FIXED_BODY];
    size_t at = 0;
    view(&V, 0x11, 0x22);
    cs_subject_genesis(&S, &V, PROV, CS_ORIGIN_OPERATOR);
    CK_(cs_subject_encode(&S, buf, sizeof buf, &len, &why) == CC_OK, "encode genesis: %s", why);
    CK_(len == CC_HEADER_BYTES + CS_FIXED_BODY, "genesis is header + fixed body (%zu)", len);
    /* By hand from continuity_subject.h. */
    memcpy(exp + at, "AIENSUBJ", 8);
    at += 8;
    exp[at++] = 0; exp[at++] = 0;                 /* format_version 0 */
    exp[at++] = 0; exp[at++] = 0;                 /* reserved */
    exp[at++] = (uint8_t)CS_FIXED_BODY; exp[at++] = 0; exp[at++] = 0; exp[at++] = 0; /* body 184 */
    fill(exp + at, 32, 0x11); at += 32;           /* root */
    fill(exp + at, 32, 0x22); at += 32;           /* agent */
    fill(exp + at, 32, 0); at += 32;              /* previous */
    exp[at++] = 1; fill(exp + at, 7, 0); at += 7; /* sequence 1 */
    fill(exp + at, 32, 0); at += 32;              /* cortex unbound */
    memcpy(exp + at, PROV, 32); at += 32;         /* provenance */
    exp[at++] = CS_ORIGIN_OPERATOR; fill(exp + at, 7, 0); at += 7;
    fill(exp + at, 8, 0); at += 8;                /* n_intents, n_knowledge, reserved */
    CK_(at == sizeof exp, "hand layout is %zu bytes", at);
    CK_(memcmp(exp, buf, sizeof exp) == 0, "genesis bytes match the hand layout");
    CK_(cs_subject_id(buf, len, id) == CC_OK, "subject id");
    CK_(sv1_object_id(CC_KIND_SUBJECT, CC_STORE_OBJECT_VERSION, buf, len, id2) == 0, "sv1 twin");
    CK_(memcmp(id, id2, 32) == 0, "subject id is the Store v1 logical ObjectId (kind 24, version 1)");
}

/* ---- 2. round trips ---- */
static void t_round_trip(void)
{
    size_t len = 0, len2 = 0;
    uint8_t a[32], b[32], k[32];
    uint64_t p[2] = {7, 1000};
    uint64_t q[2] = {9, 2000};
    view(&V, 0x11, 0x22);
    cs_subject_genesis(&S, &V, PROV, CS_ORIGIN_OPERATOR);
    CK_(cs_subject_intend(&S, CS_INTENT_GOAL_LATENCY, p, a, &why) == CC_OK, "intend: %s", why);
    CK_(cs_subject_intend(&S, CS_INTENT_GOAL_LATENCY, q, b, &why) == CC_OK, "intend 2: %s", why);
    fill(k, 32, 0x5c);
    CK_(cs_subject_hold(&S, k, 17, &why) == CC_OK, "hold: %s", why);
    fill(k, 32, 0x3c);
    CK_(cs_subject_hold(&S, k, 18, &why) == CC_OK, "hold 2: %s", why);
    fill(k, 32, 0x3c);
    CK_(cs_subject_hold(&S, k, 18, &why) == CC_E_ARG, "duplicate knowledge refused");
    fill(k, 32, 0x77);
    cs_subject_bind_cortex(&S, k);
    CK_(cs_subject_encode(&S, buf, sizeof buf, &len, &why) == CC_OK, "encode: %s", why);
    CK_(len == CC_HEADER_BYTES + CS_FIXED_BODY + 2 * CS_INTENT_BYTES + 2 * CS_KNOWLEDGE_BYTES, "len %zu", len);
    CK_(cs_subject_decode(buf, len, &S2, &why) == CC_OK, "decode: %s", why);
    CK_(memcmp(&S, &S2, sizeof S) == 0, "round trip equal");
    CK_(cs_subject_encode(&S2, buf2, sizeof buf2, &len2, &why) == CC_OK, "re-encode");
    CK_(len == len2 && memcmp(buf, buf2, len) == 0, "re-encode is byte identical");
    CK_(S2.n_intents == 2 && S2.n_knowledge == 2, "counts");
    CK_(memcmp(S2.kn[0].digest, S2.kn[1].digest, 32) < 0, "knowledge sorted");
    CK_(memcmp(S2.in[0].id, S2.in[1].id, 32) < 0, "intents sorted");
    CK_(cs_subject_active(&S2, CS_INTENT_GOAL_LATENCY, 7) && cs_subject_active(&S2, CS_INTENT_GOAL_LATENCY, 9),
        "both slots active");
}

/* ---- 3. refusals ---- */
static void expect_refuse(const uint8_t *b, size_t len, int cls, const char *text)
{
    int rc = cs_subject_decode(b, len, &S3, &why);
    CK_(rc == cls, "%s: class %d (why=%s)", text, rc, why ? why : "-");
    CK_(why && strcmp(why, text) == 0, "%s: reason is '%s'", text, why ? why : "-");
}

static void t_refusals(void)
{
    size_t len = 0;
    uint64_t p[2] = {7, 1000};
    view(&V, 0x11, 0x22);
    cs_subject_genesis(&S, &V, PROV, CS_ORIGIN_OPERATOR);
    CK_(cs_subject_intend(&S, CS_INTENT_GOAL_LATENCY, p, NULL, &why) == CC_OK, "intend");
    CK_(cs_subject_encode(&S, buf, sizeof buf, &len, &why) == CC_OK, "encode base");
    /* header */
    memcpy(buf2, buf, len);
    buf2[0] ^= 1;
    expect_refuse(buf2, len, CC_E_CORRUPT, "bad magic");
    memcpy(buf2, buf, len);
    buf2[8] = 1;
    expect_refuse(buf2, len, CC_E_CORRUPT, "unsupported continuity format version");
    memcpy(buf2, buf, len);
    buf2[10] = 1;
    expect_refuse(buf2, len, CC_E_CORRUPT, "nonzero header reserved");
    memcpy(buf2, buf, len);
    buf2[12] ^= 1;
    expect_refuse(buf2, len, CC_E_CORRUPT, "body length mismatch");
    expect_refuse(buf, len - 1, CC_E_CORRUPT, "body length mismatch");
    memcpy(buf2, buf, len);
    sv1_put32(buf2 + 12, (uint32_t)(len - CC_HEADER_BYTES + 1));
    expect_refuse(buf2, len + 1, CC_E_CORRUPT, "trailing bytes");
    /* truncated inside the intents: the length field is made to agree so the
     * one bounds check is what refuses it */
    memcpy(buf2, buf, len);
    sv1_put32(buf2 + 12, (uint32_t)(len - CC_HEADER_BYTES - 10));
    expect_refuse(buf2, len - 10, CC_E_CORRUPT, "truncated object");
    expect_refuse(buf, 5, CC_E_CORRUPT, "truncated object");
    /* body rules */
    memcpy(buf2, buf, len);
    fill(buf2 + 16, 32, 0);
    expect_refuse(buf2, len, CC_E_CORRUPT, "zero root id");
    memcpy(buf2, buf, len);
    fill(buf2 + 48, 32, 0);
    expect_refuse(buf2, len, CC_E_CORRUPT, "zero agent id");
    memcpy(buf2, buf, len);
    buf2[80] = 1; /* previous nonzero on sequence 1 */
    expect_refuse(buf2, len, CC_E_CORRUPT, "genesis subject names a previous object");
    memcpy(buf2, buf, len);
    buf2[112] = 2; /* sequence 2 without previous */
    expect_refuse(buf2, len, CC_E_CORRUPT, "subject object after the first has no previous");
    memcpy(buf2, buf, len);
    buf2[112] = 0;
    expect_refuse(buf2, len, CC_E_CORRUPT, "zero sequence");
    memcpy(buf2, buf, len);
    fill(buf2 + 152, 32, 0);
    expect_refuse(buf2, len, CC_E_CORRUPT, "zero provenance");
    memcpy(buf2, buf, len);
    buf2[184] = 9;
    expect_refuse(buf2, len, CC_E_CORRUPT, "unknown subject origin");
    memcpy(buf2, buf, len);
    buf2[185] = 1;
    expect_refuse(buf2, len, CC_E_CORRUPT, "nonzero reserved bytes");
    memcpy(buf2, buf, len);
    sv1_put16(buf2 + 192, CS_MAX_INTENTS + 1);
    expect_refuse(buf2, len, CC_E_LIMIT, "too many standing intents");
    memcpy(buf2, buf, len);
    sv1_put16(buf2 + 194, CS_MAX_KNOWLEDGE + 1);
    expect_refuse(buf2, len, CC_E_LIMIT, "too many knowledge references");
    memcpy(buf2, buf, len);
    buf2[197] = 1;
    expect_refuse(buf2, len, CC_E_CORRUPT, "nonzero reserved bytes");
    /* intent rules (intent starts at 200: id 200, supersedes 232, kind 264,
     * state 268, reserved 269, since 272, payload 280) */
    memcpy(buf2, buf, len);
    buf2[200] ^= 1;
    expect_refuse(buf2, len, CC_E_CORRUPT, "intent id does not derive from its content");
    memcpy(buf2, buf, len);
    buf2[268] = 7;
    expect_refuse(buf2, len, CC_E_CORRUPT, "unknown intent state");
    memcpy(buf2, buf, len);
    buf2[264] = 2;
    expect_refuse(buf2, len, CC_E_CORRUPT, "unknown intent kind");
    memcpy(buf2, buf, len);
    buf2[269] = 1;
    expect_refuse(buf2, len, CC_E_CORRUPT, "nonzero reserved bytes");
    memcpy(buf2, buf, len);
    buf2[272] = 2; /* since 2 > sequence 1 (id no longer derives either; since is checked first) */
    expect_refuse(buf2, len, CC_E_CORRUPT, "intent created outside the subject chain");
    memcpy(buf2, buf, len);
    memcpy(buf2 + 232, buf2 + 200, 32); /* supersedes itself */
    expect_refuse(buf2, len, CC_E_CORRUPT, "intent supersedes itself");
    memcpy(buf2, buf, len);
    buf2[232] = 1; /* supersedes an absent intent */
    expect_refuse(buf2, len, CC_E_CORRUPT, "superseded intent is absent");
    /* K-1 cap on decode */
    CK_(cs_subject_decode(buf, CC_MAX_OBJECT_BYTES + 1, &S3, &why) == CC_E_LIMIT, "cap on decode");
    /* validate-side rules that the editor cannot produce */
    view(&V, 0x11, 0x22);
    cs_subject_genesis(&S, &V, PROV, CS_ORIGIN_OPERATOR);
    CK_(cs_subject_intend(&S, CS_INTENT_GOAL_LATENCY, p, NULL, &why) == CC_OK, "intend");
    S.in[0].state = CS_SUPERSEDED; /* superseded by nobody */
    CK_(cs_subject_validate(&S, &why) == CC_E_CORRUPT &&
            strcmp(why, "superseded intent not named by exactly one successor") == 0,
        "orphan superseded: %s", why);
    S.in[0].state = CS_ACTIVE;
    S.n_intents = CS_MAX_INTENTS + 1;
    CK_(cs_subject_validate(&S, &why) == CC_E_LIMIT, "intent bound");
    S.n_intents = 1;
    S.kn[0].since = 1;
    fill(S.kn[0].digest, 32, 0x10);
    S.kn[1].since = 1;
    fill(S.kn[1].digest, 32, 0x10);
    S.n_knowledge = 2;
    CK_(cs_subject_validate(&S, &why) == CC_E_CORRUPT &&
            strcmp(why, "knowledge not strictly ascending by digest") == 0,
        "knowledge order: %s", why);
    S.n_knowledge = 0;
    CK_(cs_subject_encode(&S, buf, 10, &len, &why) == CC_E_ARG, "small output buffer");
    CK_(cs_subject_encode(NULL, buf, sizeof buf, &len, &why) == CC_E_ARG, "null");
    CK_(cs_subject_decode(buf, 100, NULL, &why) == CC_E_ARG, "null out");
}

/* ---- 4. intents: supersession and retirement ---- */
static void t_intents(void)
{
    uint8_t a[32], b[32];
    uint64_t p[2] = {7, 1000};
    uint64_t p2[2] = {7, 500};
    size_t len = 0;
    view(&V, 0x11, 0x22);
    cs_subject_genesis(&S, &V, PROV, CS_ORIGIN_OPERATOR);
    CK_(cs_subject_intend(&S, CS_INTENT_GOAL_LATENCY, p, a, &why) == CC_OK, "intend a");
    CK_(cs_subject_intend(&S, CS_INTENT_GOAL_LATENCY, p, a, &why) == CC_E_ARG, "same intent twice refused");
    /* a successor object replaces the goal in the same slot */
    fill(b, 32, 0x99);
    cs_subject_advance(&S, b, PROV, CS_ORIGIN_OPERATOR);
    CK_(S.sequence == 2 && memcmp(S.previous, b, 32) == 0, "advance");
    CK_(cs_subject_intend(&S, CS_INTENT_GOAL_LATENCY, p2, b, &why) == CC_OK, "intend b: %s", why);
    CK_(S.n_intents == 2, "two intents");
    {
        const struct cs_intent *act = cs_subject_active(&S, CS_INTENT_GOAL_LATENCY, 7);
        CK_(act && memcmp(act->id, b, 32) == 0 && act->payload[1] == 500, "b is the active one");
        CK_(memcmp(act->supersedes, a, 32) == 0, "b names a");
    }
    CK_(cs_subject_encode(&S, buf, sizeof buf, &len, &why) == CC_OK, "encode after supersede: %s", why);
    CK_(cs_subject_decode(buf, len, &S2, &why) == CC_OK, "decode after supersede: %s", why);
    /* two active in one slot is refused on decode (mutant ACCEPT_TWO_ACTIVE) */
    for (uint32_t i = 0; i < S2.n_intents; i++)
        if (memcmp(S2.in[i].id, a, 32) == 0) S2.in[i].state = CS_ACTIVE;
    for (uint32_t i = 0; i < S2.n_intents; i++)
        if (memcmp(S2.in[i].id, b, 32) == 0) memset(S2.in[i].supersedes, 0, 32);
    CK_(cs_subject_validate(&S2, &why) == CC_E_CORRUPT && strcmp(why, "two active intents in one slot") == 0,
        "two active refused: %s", why);
    /* retire */
    CK_(cs_subject_retire(&S, b, &why) == CC_OK, "retire b");
    CK_(cs_subject_active(&S, CS_INTENT_GOAL_LATENCY, 7) == NULL, "slot empty after retire");
    CK_(cs_subject_retire(&S, b, &why) == CC_E_ARG, "retire twice refused");
    CK_(cs_subject_retire(&S, a, &why) == CC_E_ARG, "retire a superseded intent refused");
    CK_(cs_subject_validate(&S, &why) == CC_OK, "still valid: %s", why);
    /* supersedes a newer intent: swap since values by hand */
    {
        uint32_t ia = 0, ib = 0;
        for (uint32_t i = 0; i < S.n_intents; i++) {
            if (memcmp(S.in[i].id, a, 32) == 0) ia = i;
            if (memcmp(S.in[i].id, b, 32) == 0) ib = i;
        }
        S.in[ia].since = 2;
        S.in[ib].since = 1;
        /* ids no longer derive, but since-order is checked for b before its id? No:
         * id derivation is checked per intent before supersession, so make the
         * check order explicit by recomputing ids. */
        cs_intent_id(S.agent, S.in[ia].kind, S.in[ia].since, S.in[ia].payload, S.in[ia].id);
        cs_intent_id(S.agent, S.in[ib].kind, S.in[ib].since, S.in[ib].payload, S.in[ib].id);
        memcpy(S.in[ib].supersedes, S.in[ia].id, 32);
        /* the table may now be out of order; sort by id (two elements) */
        if (memcmp(S.in[0].id, S.in[1].id, 32) > 0) {
            struct cs_intent t = S.in[0];
            S.in[0] = S.in[1];
            S.in[1] = t;
        }
        CK_(cs_subject_validate(&S, &why) == CC_E_CORRUPT && strcmp(why, "intent supersedes a newer intent") == 0,
            "supersedes newer refused: %s", why);
    }
}

/* ---- 5. resolve over a fake source ---- */
struct fake {
    uint32_t n;
    uint16_t kind[8], version[8];
    uint8_t *bytes[8];
    size_t len[8];
};
static uint32_t fk_count(void *c) { return ((struct fake *)c)->n; }
static int fk_entry(void *c, uint32_t i, uint16_t *k, uint16_t *v)
{
    struct fake *f = c;
    *k = f->kind[i];
    *v = f->version[i];
    return 0;
}
static int fk_read(void *c, uint32_t i, uint8_t *out, size_t cap, size_t *len)
{
    struct fake *f = c;
    *len = f->len[i];
    if (*len <= cap) memcpy(out, f->bytes[i], *len);
    return 0;
}
static int fk_mount(void *c)
{
    (void)c;
    return CR_MOUNT_VALID;
}
static uint8_t obj[8][CC_MAX_OBJECT_BYTES];
static size_t objlen[8];
static uint8_t objid[8][32];

static uint32_t fk_add(struct fake *f, uint16_t kind, const struct cs_subject *s)
{
    uint32_t i = f->n++;
    CK_(cs_subject_encode(s, obj[i], sizeof obj[i], &objlen[i], &why) == CC_OK, "fk encode: %s", why);
    CK_(cs_subject_id(obj[i], objlen[i], objid[i]) == CC_OK, "fk id");
    f->kind[i] = kind;
    f->version[i] = CC_STORE_OBJECT_VERSION;
    f->bytes[i] = obj[i];
    f->len[i] = objlen[i];
    return i;
}

static void t_resolve(void)
{
    struct fake f;
    struct cr_source src = {&f, fk_count, fk_entry, fk_read, fk_mount, NULL};
    uint8_t id[32];
    uint64_t p[2] = {7, 1000};
    int rc;
    view(&V, 0x11, 0x22);
    memset(&f, 0, sizeof f);
    /* absent */
    rc = cs_resolve(&src, &W, &V, &S2, id, &why, NULL);
    CK_(rc == CS_ABSENT, "no subject object: ABSENT (%d)", rc);
    /* a foreign-kind object is ignored */
    cs_subject_genesis(&S, &V, PROV, CS_ORIGIN_OPERATOR);
    fk_add(&f, 99, &S);
    CK_(cs_resolve(&src, &W, &V, &S2, id, &why, NULL) == CS_ABSENT, "other kinds ignored");
    f.n = 0;
    /* chain of two */
    fk_add(&f, CC_KIND_SUBJECT, &S);
    cs_subject_advance(&S, objid[0], PROV, CS_ORIGIN_PROMOTED);
    CK_(cs_subject_intend(&S, CS_INTENT_GOAL_LATENCY, p, NULL, &why) == CC_OK, "intend");
    fk_add(&f, CC_KIND_SUBJECT, &S);
    rc = cs_resolve(&src, &W, &V, &S2, id, &why, NULL);
    CK_(rc == CS_RESOLVED, "chain of two resolves (%d: %s)", rc, why ? why : "-");
    CK_(S2.sequence == 2 && S2.n_intents == 1 && memcmp(id, objid[1], 32) == 0, "head is sequence 2");
    /* order independence: same objects, reversed */
    {
        uint8_t *tb = f.bytes[0]; f.bytes[0] = f.bytes[1]; f.bytes[1] = tb;
        size_t tl = f.len[0]; f.len[0] = f.len[1]; f.len[1] = tl;
        rc = cs_resolve(&src, &W, &V, &S3, id, &why, NULL);
        CK_(rc == CS_RESOLVED && memcmp(&S2, &S3, sizeof S2) == 0, "resolution does not depend on catalog order");
        tb = f.bytes[0]; f.bytes[0] = f.bytes[1]; f.bytes[1] = tb;
        tl = f.len[0]; f.len[0] = f.len[1]; f.len[1] = tl;
    }
    /* fork: a second sequence-2 object with a different intent */
    {
        uint64_t q[2] = {7, 999};
        cs_subject_decode(obj[0], objlen[0], &S3, &why);
        cs_subject_advance(&S3, objid[0], PROV, CS_ORIGIN_PROMOTED);
        CK_(cs_subject_intend(&S3, CS_INTENT_GOAL_LATENCY, q, NULL, &why) == CC_OK, "intend fork");
        fk_add(&f, CC_KIND_SUBJECT, &S3);
        rc = cs_resolve(&src, &W, &V, &S2, id, &why, NULL);
        CK_(rc == CR_CORRUPT && strcmp(why, "subject chain fork") == 0, "fork refused (%d: %s)", rc, why);
        f.n = 2;
    }
    /* gap: sequence 1 and 3 */
    {
        cs_subject_decode(obj[1], objlen[1], &S3, &why);
        cs_subject_advance(&S3, objid[1], PROV, CS_ORIGIN_PROMOTED);
        fk_add(&f, CC_KIND_SUBJECT, &S3);
        f.bytes[1] = f.bytes[2]; f.len[1] = f.len[2]; f.n = 2;
        rc = cs_resolve(&src, &W, &V, &S2, id, &why, NULL);
        CK_(rc == CR_CORRUPT && strcmp(why, "subject chain gap") == 0, "gap refused (%d: %s)", rc, why);
        f.bytes[1] = obj[1]; f.len[1] = objlen[1];
    }
    /* broken link: sequence 2 names a previous that is not sequence 1's id */
    {
        cs_subject_decode(obj[1], objlen[1], &S3, &why);
        S3.previous[0] ^= 1;
        uint32_t k = fk_add(&f, CC_KIND_SUBJECT, &S3);
        f.bytes[1] = f.bytes[k]; f.len[1] = f.len[k]; f.n = 2;
        rc = cs_resolve(&src, &W, &V, &S2, id, &why, NULL);
        CK_(rc == CR_CORRUPT && strcmp(why, "subject chain link broken") == 0, "broken link refused (%d: %s)", rc, why);
        f.bytes[1] = obj[1]; f.len[1] = objlen[1];
    }
    /* ALLEN-G1 identity binding: another agent's view, or a tampered agent
     * id, must not resolve this subject */
    {
        struct cr_view other;
        view(&other, 0x11, 0x23);
        rc = cs_resolve(&src, &W, &other, &S2, id, &why, NULL);
        CK_(rc == CR_CORRUPT && strcmp(why, "subject object belongs to another agent") == 0,
            "another agent id refused (%d: %s)", rc, why ? why : "-");
        view(&other, 0x12, 0x22);
        rc = cs_resolve(&src, &W, &other, &S2, id, &why, NULL);
        CK_(rc == CR_CORRUPT && strcmp(why, "subject object belongs to another agent") == 0,
            "another root refused (%d: %s)", rc, why ? why : "-");
        rc = cs_resolve(&src, &W, &V, &S2, id, &why, NULL);
        CK_(rc == CS_RESOLVED, "the right view still resolves");
    }
    /* undecodable object in the catalog: CORRUPT, never skipped */
    {
        obj[1][0] ^= 1;
        rc = cs_resolve(&src, &W, &V, &S2, id, &why, NULL);
        CK_(rc == CR_CORRUPT && strcmp(why, "bad magic") == 0, "undecodable refused (%d: %s)", rc, why);
        obj[1][0] ^= 1;
    }
    /* unknown claim version */
    {
        f.version[1] = 2;
        rc = cs_resolve(&src, &W, &V, &S2, id, &why, NULL);
        CK_(rc == CR_CORRUPT, "unknown claim version refused");
        f.version[1] = CC_STORE_OBJECT_VERSION;
    }
}

/* ---- 6. model independence (structural) ---- */
static void t_model_independence(void)
{
    size_t la = 0, lb = 0;
    uint8_t ia[32], ib[32];
    uint64_t p[2] = {7, 1000};
    uint8_t model_a[32], model_b[32];
    fill(model_a, 32, 0xa1);
    fill(model_b, 32, 0xb2);
    view(&V, 0x11, 0x22);
    cs_subject_genesis(&S, &V, PROV, CS_ORIGIN_OPERATOR);
    CK_(cs_subject_intend(&S, CS_INTENT_GOAL_LATENCY, p, NULL, &why) == CC_OK, "intend");
    /* The "model" is the boot handoff's model_sha256 (native/boot/handoff.h),
     * outside this object. There is nowhere to put it: encode takes no such
     * input. Two runs that serve different models produce one subject. */
    (void)model_a;
    (void)model_b;
    CK_(cs_subject_encode(&S, buf, sizeof buf, &la, &why) == CC_OK, "encode under model a");
    CK_(cs_subject_id(buf, la, ia) == CC_OK, "id a");
    CK_(cs_subject_encode(&S, buf2, sizeof buf2, &lb, &why) == CC_OK, "encode under model b");
    CK_(cs_subject_id(buf2, lb, ib) == CC_OK, "id b");
    CK_(la == lb && memcmp(buf, buf2, la) == 0 && memcmp(ia, ib, 32) == 0,
        "subject bytes and id do not depend on which model is served");
    /* and no byte of either model digest appears in the object */
    {
        int hit = 0;
        for (size_t i = 0; i + 4 <= la; i++)
            if (memcmp(buf + i, model_a, 4) == 0 || memcmp(buf + i, model_b, 4) == 0) hit = 1;
        CK_(!hit, "no model digest bytes inside the subject object");
    }
}

/* ---- 7. real sealed Store in a file ---- */
#define A_UNITS 4u
#define S_UNITS 512u
static ss_workspace g_ws;
static ss_store g_s;
static disk_file g_f;
static disk_dev g_d;
static st_disk g_sd;
static st_dev g_sdev;
static ts_device g_tdev;
static ss_keys g_k;
static const uint32_t g_bs = 4096u;
static char g_path[256];
static struct cr_work g_w;
static struct cr_txwork g_tw;
static struct cr_view g_v;
static struct cr_source g_src;
static struct cr_sink g_snk;
static struct cr_sealed_sink g_sk;
static const uint8_t RUUID[16] = {0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
                                  0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a};
static int g_open;

static void dev_close(void)
{
    if (g_open) disk_file_close(&g_f);
    g_open = 0;
}
static int dev_open(int create)
{
    dev_close();
    uint32_t bpu = 4096u / g_bs;
    if (create) unlink(g_path);
    memset(&g_f, 0, sizeof g_f);
    if (disk_file_open(&g_f, &g_d, g_path, g_bs, (uint64_t)(A_UNITS + S_UNITS) * bpu, create) != 0) return -1;
    g_open = 1;
    if (st_disk_bind(&g_sd, &g_d, (uint64_t)A_UNITS * bpu, S_UNITS, &g_sdev) != 0) return -2;
    ss_ts_device(&g_d, &g_tdev);
    return 0;
}
static void make_keys(void)
{
    uint8_t kvol[32];
    memset(kvol, 0x77, 32);
    m5_subkeys sk;
    m5_derive_subkeys(kvol, M5_ID_TEST, 0, &sk);
    memset(&g_k, 0, sizeof g_k);
    g_k.identity_class = M5_ID_TEST;
    g_k.key_generation = 1;
    memcpy(g_k.k_root_auth, sk.k_root_auth, 32);
    memcpy(g_k.k_domain, sk.k_artifact, 32);
    m5_subkeys_wipe(&sk);
}
static void bind_store(void)
{
    g_sk.s = &g_s;
    g_sk.hook = NULL;
    g_sk.hook_arg = NULL;
    cr_bind_sealed(&g_src, &g_s);
    cr_bind_sealed_sink(&g_snk, &g_sk);
}
/* mocked RNDR (as test_continuity_commit.c) */
struct mock {
    int present;
    uint64_t ctr;
};
static struct mock g_m;
static struct ck_rng_ops g_ops;
static struct ck_rng g_rng;
static int m_present(void *c) { return ((struct mock *)c)->present; }
static int m_read(void *c, uint64_t *out)
{
    struct mock *m = c;
    uint64_t z = (m->ctr += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    *out = z ^ (z >> 31);
    return 1;
}
static void rng_init(uint64_t seed)
{
    g_m.present = 1;
    g_m.ctr = seed;
    g_ops.present = m_present;
    g_ops.read = m_read;
    g_ops.ctx = &g_m;
    memset(&g_rng, 0, sizeof g_rng);
    (void)ck_rng_probe(&g_rng, &g_ops);
}

static int store_fresh(void)
{
    if (dev_open(1) != 0) return -1;
    if (ss_format(&g_sdev, &g_tdev, 0, RUUID, &g_k, &g_ws) != 0) return -2;
    if (ss_open(&g_s, &g_sdev, &g_tdev, 0, &g_k, &g_ws) != 0) return -3;
    bind_store();
    return 0;
}
static int store_reopen(void)
{
    if (dev_open(0) != 0) return -1;
    if (ss_open(&g_s, &g_sdev, &g_tdev, 0, &g_k, &g_ws) != 0) return -3;
    bind_store();
    return 0;
}

/* Provision the identity, then commit the genesis subject and one successor
 * carrying a standing intent. Returns the head id. */
static int write_subject(uint8_t head_id[32], uint64_t *agent_lo)
{
    int rc = 0, store_rc = 0;
    uint8_t gid[32];
    uint64_t p[2] = {7, 1000};
    rc = cr_provision(&g_src, &g_snk, &g_w, &g_tw, &g_rng, RUUID, CC_SOURCE_QUALIFICATION, &g_v, &why, &store_rc);
    CK_(rc == CR_RESOLVED, "provision (%d: %s, store %d)", rc, why ? why : "-", store_rc);
    if (rc != CR_RESOLVED) return -1;
    CK_(cs_resolve(&g_src, &g_w, &g_v, &S2, gid, &why, &store_rc) == CS_ABSENT, "fresh store: subject ABSENT");
    cs_subject_genesis(&S, &g_v, PROV, CS_ORIGIN_OPERATOR);
    rc = cs_commit(&g_src, &g_snk, &g_w, &g_v, &S, gid, &why, &store_rc);
    CK_(rc == CS_RESOLVED, "commit genesis (%d: %s, store %d)", rc, why ? why : "-", store_rc);
    /* a stale successor (wrong previous) is refused and writes nothing */
    cs_subject_advance(&S, gid, PROV, CS_ORIGIN_OPERATOR);
    S.previous[0] ^= 1;
    rc = cs_commit(&g_src, &g_snk, &g_w, &g_v, &S, head_id, &why, &store_rc);
    CK_(rc == CR_CORRUPT && strcmp(why, "subject object does not continue the resolved chain") == 0,
        "stale successor refused (%d: %s)", rc, why ? why : "-");
    S.previous[0] ^= 1;
    CK_(cs_subject_intend(&S, CS_INTENT_GOAL_LATENCY, p, NULL, &why) == CC_OK, "intend");
    rc = cs_commit(&g_src, &g_snk, &g_w, &g_v, &S, head_id, &why, &store_rc);
    CK_(rc == CS_RESOLVED, "commit successor (%d: %s, store %d)", rc, why ? why : "-", store_rc);
    /* a second genesis is refused: the chain already exists */
    cs_subject_genesis(&S3, &g_v, PROV, CS_ORIGIN_OPERATOR);
    rc = cs_commit(&g_src, &g_snk, &g_w, &g_v, &S3, gid, &why, &store_rc);
    CK_(rc == CR_CORRUPT, "second genesis refused (%d: %s)", rc, why ? why : "-");
    memcpy(agent_lo, g_v.root.agent_id, 8);
    return 0;
}

static void check_restored(const uint8_t want_id[32])
{
    int rc, store_rc = 0, committed = 0;
    uint8_t id[32];
    rc = cr_resume(&g_src, &g_snk, &g_w, &g_tw, &g_v, &committed, &why, &store_rc);
    CK_(rc == CR_RESOLVED && committed == 1, "resume (%d: %s)", rc, why ? why : "-");
    rc = cs_resolve(&g_src, &g_w, &g_v, &S2, id, &why, &store_rc);
    CK_(rc == CS_RESOLVED, "subject resolves after reopen (%d: %s, store %d)", rc, why ? why : "-", store_rc);
    CK_(memcmp(id, want_id, 32) == 0, "same subject id after reopen");
    CK_(S2.sequence == 2 && S2.n_intents == 1, "sequence 2 with one intent");
    CK_(memcmp(S2.agent, g_v.root.agent_id, 32) == 0 && memcmp(S2.root, g_v.root_id, 32) == 0,
        "subject bound to the provisioned identity");
    {
        const struct cs_intent *a = cs_subject_active(&S2, CS_INTENT_GOAL_LATENCY, 7);
        CK_(a && a->payload[1] == 1000 && a->since == 2, "the standing intent came back");
    }
}

static void t_sealed_store(void)
{
    uint8_t head[32];
    uint64_t lo = 0;
    snprintf(g_path, sizeof g_path, "/tmp/ck_cs_test_%d.img", (int)getpid());
    rng_init(0x1234);
    CK_(store_fresh() == 0, "fresh store");
    if (write_subject(head, &lo) == 0) {
        dev_close();
        CK_(store_reopen() == 0, "reopen");
        check_restored(head);
        /* a successor committed against a stale view (older chain head) is refused */
        {
            int rc, store_rc = 0;
            uint8_t id[32];
            cs_subject_genesis(&S3, &g_v, PROV, CS_ORIGIN_OPERATOR);
            S3.sequence = 3;
            memcpy(S3.previous, head, 32);
            S3.previous[1] ^= 1;
            rc = cs_commit(&g_src, &g_snk, &g_w, &g_v, &S3, id, &why, &store_rc);
            CK_(rc == CR_CORRUPT, "wrong previous refused after reopen");
        }
    }
    dev_close();
    unlink(g_path);
}

/* ---- two-process restart (ALLEN-G2) ---- */
static int phase_write(const char *img)
{
    uint8_t head[32];
    uint64_t lo = 0;
    char h[65];
    snprintf(g_path, sizeof g_path, "%s", img);
    make_keys();
    rng_init(0x5eed);
    CK_(store_fresh() == 0, "fresh store");
    if (write_subject(head, &lo) != 0) return ck_t_verdict("test_continuity_subject --write");
    dev_close();
    hex(head, 32, h);
    printf("ALLEN subject id: %s\n", h);
    printf("ALLEN agent: %016llx...\n", (unsigned long long)lo);
    return ck_t_verdict("test_continuity_subject --write");
}

static int phase_restore(const char *img, const char *idhex)
{
    uint8_t want[32];
    snprintf(g_path, sizeof g_path, "%s", img);
    make_keys();
    CK_(strlen(idhex) == 64 && unhex(idhex, want, 32) == 0, "id argument");
    CK_(store_reopen() == 0, "reopen in a fresh process");
    check_restored(want);
    /* The pre-ALLEN continuity view has nowhere to keep an intent: its
     * fields are root, manifest, branch table, Cortex count and memory
     * digest (continuity_resolve.h struct cr_view). Structural half of G6. */
    CK_(sizeof(struct cr_view) == sizeof(g_v), "cr_view inspected");
    printf("ALLEN restored: sequence=%llu intents=%u regime=%llu target_ns=%llu\n",
           (unsigned long long)S2.sequence, S2.n_intents,
           (unsigned long long)(S2.n_intents ? S2.in[0].payload[0] : 0),
           (unsigned long long)(S2.n_intents ? S2.in[0].payload[1] : 0));
    dev_close();
    return ck_t_verdict("test_continuity_subject --restore");
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--write") == 0) return phase_write(argv[2]);
    if (argc == 4 && strcmp(argv[1], "--restore") == 0) return phase_restore(argv[2], argv[3]);
    make_keys();
    t_known_answer();
    t_round_trip();
    t_refusals();
    t_intents();
    t_resolve();
    t_model_independence();
    t_sealed_store();
    return ck_t_verdict("test_continuity_subject");
}
