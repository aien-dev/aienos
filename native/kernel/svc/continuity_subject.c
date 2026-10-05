/* continuity_subject.c -- ALLEN subject state (kind 24): codec, editing,
 * resolve and commit. See continuity_subject.h for the format and rules. */
#include "continuity_subject.h"

#include "sha256.h"
#include "store_v1.h"

static const uint8_t MAGIC_SUBJECT[8] = {'A', 'I', 'E', 'N', 'S', 'U', 'B', 'J'};
static const char INTENT_DOMAIN[] = "AIENOS_INTENT_v0:";

static int fail(const char **why, int cls, const char *w)
{
    if (why)
        *why = w;
    return cls;
}

/* ---- intent identity ---- */
void cs_intent_id(const uint8_t agent[32], uint32_t kind, uint64_t since, const uint64_t payload[2],
                  uint8_t out[32])
{
    sha256_ctx c;
    uint8_t b[8];
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)INTENT_DOMAIN, sizeof INTENT_DOMAIN - 1);
    sha256_update(&c, agent, 32);
    sv1_put32(b, kind);
    sha256_update(&c, b, 4);
    sv1_put64(b, since);
    sha256_update(&c, b, 8);
    sv1_put64(b, payload[0]);
    sha256_update(&c, b, 8);
    sv1_put64(b, payload[1]);
    sha256_update(&c, b, 8);
    sha256_final(&c, out);
}

/* ---- validation (every rule the decoder enforces, usable before encode) ---- */
static int state_ok(uint8_t s)
{
    return s == CS_ACTIVE || s == CS_INACTIVE || s == CS_SUPERSEDED;
}

int cs_subject_validate(const struct cs_subject *s, const char **why)
{
    if (!s)
        return fail(why, CC_E_ARG, "null argument");
    if (sv1_all_zero(s->root, 32))
        return fail(why, CC_E_CORRUPT, "zero root id");
    if (sv1_all_zero(s->agent, 32))
        return fail(why, CC_E_CORRUPT, "zero agent id");
    if (s->sequence == 0)
        return fail(why, CC_E_CORRUPT, "zero sequence");
    if (s->sequence == 1 && !sv1_all_zero(s->previous, 32))
        return fail(why, CC_E_CORRUPT, "genesis subject names a previous object");
    if (s->sequence > 1 && sv1_all_zero(s->previous, 32))
        return fail(why, CC_E_CORRUPT, "subject object after the first has no previous");
    if (sv1_all_zero(s->provenance, 32))
        return fail(why, CC_E_CORRUPT, "zero provenance");
    if (s->origin != CS_ORIGIN_OPERATOR && s->origin != CS_ORIGIN_PROMOTED)
        return fail(why, CC_E_CORRUPT, "unknown subject origin");
    if (s->n_intents > CS_MAX_INTENTS)
        return fail(why, CC_E_LIMIT, "too many standing intents");
    if (s->n_knowledge > CS_MAX_KNOWLEDGE)
        return fail(why, CC_E_LIMIT, "too many knowledge references");
    for (uint32_t i = 0; i < s->n_intents; i++) {
        const struct cs_intent *a = &s->in[i];
        uint8_t id[32];
        if (i > 0 && sv1_cmp_id(s->in[i - 1].id, a->id) >= 0)
            return fail(why, CC_E_CORRUPT, "intents not strictly ascending by id");
        if (!state_ok(a->state))
            return fail(why, CC_E_CORRUPT, "unknown intent state");
        if (a->kind != CS_INTENT_GOAL_LATENCY)
            return fail(why, CC_E_CORRUPT, "unknown intent kind");
        if (a->since == 0 || a->since > s->sequence)
            return fail(why, CC_E_CORRUPT, "intent created outside the subject chain");
        cs_intent_id(s->agent, a->kind, a->since, a->payload, id);
#ifndef CS_MUTANT_SKIP_INTENT_ID
        if (!sv1_equal(id, a->id, 32))
            return fail(why, CC_E_CORRUPT, "intent id does not derive from its content");
#endif
        if (!sv1_all_zero(a->supersedes, 32)) {
            uint32_t j;
            if (sv1_equal(a->supersedes, a->id, 32))
                return fail(why, CC_E_CORRUPT, "intent supersedes itself");
            for (j = 0; j < s->n_intents; j++)
                if (sv1_equal(s->in[j].id, a->supersedes, 32))
                    break;
            if (j == s->n_intents)
                return fail(why, CC_E_CORRUPT, "superseded intent is absent");
            if (s->in[j].state != CS_SUPERSEDED)
                return fail(why, CC_E_CORRUPT, "superseded intent is not marked superseded");
            if (s->in[j].since > a->since)
                return fail(why, CC_E_CORRUPT, "intent supersedes a newer intent");
        }
#ifndef CS_MUTANT_ACCEPT_TWO_ACTIVE
        if (a->state == CS_ACTIVE)
            for (uint32_t j = 0; j < i; j++)
                if (s->in[j].state == CS_ACTIVE && s->in[j].kind == a->kind &&
                    s->in[j].payload[0] == a->payload[0])
                    return fail(why, CC_E_CORRUPT, "two active intents in one slot");
#endif
    }
    /* Every SUPERSEDED intent is named by exactly one other intent. */
    for (uint32_t i = 0; i < s->n_intents; i++) {
        if (s->in[i].state != CS_SUPERSEDED)
            continue;
        uint32_t named = 0;
        for (uint32_t j = 0; j < s->n_intents; j++)
            if (sv1_equal(s->in[j].supersedes, s->in[i].id, 32))
                named++;
        if (named != 1)
            return fail(why, CC_E_CORRUPT, "superseded intent not named by exactly one successor");
    }
    for (uint32_t i = 0; i < s->n_knowledge; i++) {
        const struct cs_knowledge *k = &s->kn[i];
        if (sv1_all_zero(k->digest, 32))
            return fail(why, CC_E_CORRUPT, "zero knowledge digest");
        if (i > 0 && sv1_cmp_id(s->kn[i - 1].digest, k->digest) >= 0)
            return fail(why, CC_E_CORRUPT, "knowledge not strictly ascending by digest");
        if (k->since == 0 || k->since > s->sequence)
            return fail(why, CC_E_CORRUPT, "knowledge held outside the subject chain");
    }
    return CC_OK;
}

/* ---- encode ---- */
static size_t body_len(const struct cs_subject *s)
{
    return CS_FIXED_BODY + (size_t)s->n_intents * CS_INTENT_BYTES +
           (size_t)s->n_knowledge * CS_KNOWLEDGE_BYTES;
}

int cs_subject_encode(const struct cs_subject *s, uint8_t *out, size_t cap, size_t *len,
                      const char **why)
{
    int e;
    size_t body, total, at = 0;
    if (!s || !len)
        return fail(why, CC_E_ARG, "null argument");
    *len = 0;
    if ((e = cs_subject_validate(s, why)))
        return e;
    body = body_len(s);
    total = CC_HEADER_BYTES + body;
    if (total > CC_MAX_OBJECT_BYTES)
        return fail(why, CC_E_LIMIT, "continuity object exceeds the 16384-byte sealed Store cap");
    if (!out || cap < total)
        return fail(why, CC_E_ARG, "output buffer too small");
    sv1_copy(out + at, MAGIC_SUBJECT, 8);
    at += 8;
    sv1_put16(out + at, CC_FORMAT_VERSION);
    at += 2;
    sv1_put16(out + at, 0);
    at += 2;
    sv1_put32(out + at, (uint32_t)body);
    at += 4;
    sv1_copy(out + at, s->root, 32);
    at += 32;
    sv1_copy(out + at, s->agent, 32);
    at += 32;
    sv1_copy(out + at, s->previous, 32);
    at += 32;
    sv1_put64(out + at, s->sequence);
    at += 8;
    sv1_copy(out + at, s->cortex, 32);
    at += 32;
    sv1_copy(out + at, s->provenance, 32);
    at += 32;
    out[at++] = s->origin;
    sv1_zero(out + at, 7);
    at += 7;
    sv1_put16(out + at, (uint16_t)s->n_intents);
    at += 2;
    sv1_put16(out + at, (uint16_t)s->n_knowledge);
    at += 2;
    sv1_put32(out + at, 0);
    at += 4;
    for (uint32_t i = 0; i < s->n_intents; i++) {
        const struct cs_intent *a = &s->in[i];
        sv1_copy(out + at, a->id, 32);
        at += 32;
        sv1_copy(out + at, a->supersedes, 32);
        at += 32;
        sv1_put32(out + at, a->kind);
        at += 4;
        out[at++] = a->state;
        sv1_zero(out + at, 3);
        at += 3;
        sv1_put64(out + at, a->since);
        at += 8;
        sv1_put64(out + at, a->payload[0]);
        at += 8;
        sv1_put64(out + at, a->payload[1]);
        at += 8;
    }
    for (uint32_t i = 0; i < s->n_knowledge; i++) {
        const struct cs_knowledge *k = &s->kn[i];
        sv1_copy(out + at, k->digest, 32);
        at += 32;
        sv1_put64(out + at, k->record);
        at += 8;
        sv1_put64(out + at, k->since);
        at += 8;
    }
    *len = at;
    return CC_OK;
}

/* ---- decode: one bounds check, every rule, no trailing bytes ---- */
struct rd {
    const uint8_t *b;
    size_t len, at;
};

static int take(struct rd *r, size_t n, const uint8_t **p, const char **why)
{
    if (n > r->len - r->at)
        return fail(why, CC_E_CORRUPT, "truncated object");
    *p = r->b + r->at;
    r->at += n;
    return CC_OK;
}

static int rd_zeros(struct rd *r, size_t n, const char **why)
{
    const uint8_t *p;
    int e;
    if ((e = take(r, n, &p, why)))
        return e;
    if (!sv1_all_zero(p, n))
        return fail(why, CC_E_CORRUPT, "nonzero reserved bytes");
    return CC_OK;
}

int cs_subject_decode(const uint8_t *in, size_t len, struct cs_subject *s, const char **why)
{
    struct rd r;
    const uint8_t *p;
    int e;
    uint32_t v;
    if (!in || !s)
        return fail(why, CC_E_ARG, "null argument");
    sv1_zero(s, sizeof *s);
    r.b = in;
    r.len = len;
    r.at = 0;
    if (len > CC_MAX_OBJECT_BYTES)
        return fail(why, CC_E_LIMIT, "continuity object exceeds the 16384-byte sealed Store cap");
    if ((e = take(&r, 8, &p, why)))
        return e;
    if (!sv1_equal(p, MAGIC_SUBJECT, 8))
        return fail(why, CC_E_CORRUPT, "bad magic");
    if ((e = take(&r, 2, &p, why)))
        return e;
    if (sv1_get16(p) != CC_FORMAT_VERSION)
        return fail(why, CC_E_CORRUPT, "unsupported continuity format version");
    if ((e = rd_zeros(&r, 2, why)))
        return fail(why, e, "nonzero header reserved");
    if ((e = take(&r, 4, &p, why)))
        return e;
    if (sv1_get32(p) != (uint32_t)(len - CC_HEADER_BYTES))
        return fail(why, CC_E_CORRUPT, "body length mismatch");
    if ((e = take(&r, 32, &p, why)))
        return e;
    sv1_copy(s->root, p, 32);
    if ((e = take(&r, 32, &p, why)))
        return e;
    sv1_copy(s->agent, p, 32);
    if ((e = take(&r, 32, &p, why)))
        return e;
    sv1_copy(s->previous, p, 32);
    if ((e = take(&r, 8, &p, why)))
        return e;
    s->sequence = sv1_get64(p);
    if ((e = take(&r, 32, &p, why)))
        return e;
    sv1_copy(s->cortex, p, 32);
    if ((e = take(&r, 32, &p, why)))
        return e;
    sv1_copy(s->provenance, p, 32);
    if ((e = take(&r, 1, &p, why)))
        return e;
    s->origin = p[0];
    if ((e = rd_zeros(&r, 7, why)))
        return e;
    if ((e = take(&r, 2, &p, why)))
        return e;
    v = sv1_get16(p);
    if (v > CS_MAX_INTENTS)
        return fail(why, CC_E_LIMIT, "too many standing intents");
    s->n_intents = v;
    if ((e = take(&r, 2, &p, why)))
        return e;
    v = sv1_get16(p);
    if (v > CS_MAX_KNOWLEDGE)
        return fail(why, CC_E_LIMIT, "too many knowledge references");
    s->n_knowledge = v;
    if ((e = rd_zeros(&r, 4, why)))
        return e;
    for (uint32_t i = 0; i < s->n_intents; i++) {
        struct cs_intent *a = &s->in[i];
        if ((e = take(&r, 32, &p, why)))
            return e;
        sv1_copy(a->id, p, 32);
        if ((e = take(&r, 32, &p, why)))
            return e;
        sv1_copy(a->supersedes, p, 32);
        if ((e = take(&r, 4, &p, why)))
            return e;
        a->kind = sv1_get32(p);
        if ((e = take(&r, 1, &p, why)))
            return e;
        a->state = p[0];
        if ((e = rd_zeros(&r, 3, why)))
            return e;
        if ((e = take(&r, 8, &p, why)))
            return e;
        a->since = sv1_get64(p);
        if ((e = take(&r, 8, &p, why)))
            return e;
        a->payload[0] = sv1_get64(p);
        if ((e = take(&r, 8, &p, why)))
            return e;
        a->payload[1] = sv1_get64(p);
    }
    for (uint32_t i = 0; i < s->n_knowledge; i++) {
        struct cs_knowledge *k = &s->kn[i];
        if ((e = take(&r, 32, &p, why)))
            return e;
        sv1_copy(k->digest, p, 32);
        if ((e = take(&r, 8, &p, why)))
            return e;
        k->record = sv1_get64(p);
        if ((e = take(&r, 8, &p, why)))
            return e;
        k->since = sv1_get64(p);
    }
    if (r.at != r.len)
        return fail(why, CC_E_CORRUPT, "trailing bytes");
    return cs_subject_validate(s, why);
}

int cs_subject_id(const uint8_t *bytes, size_t len, uint8_t out[32])
{
    return cc_object_id(CC_KIND_SUBJECT, bytes, len, out);
}

/* ---- editing ---- */
void cs_subject_genesis(struct cs_subject *s, const struct cr_view *v, const uint8_t provenance[32],
                        uint8_t origin)
{
    sv1_zero(s, sizeof *s);
    sv1_copy(s->root, v->root_id, 32);
    sv1_copy(s->agent, v->root.agent_id, 32);
    s->sequence = 1;
    sv1_copy(s->provenance, provenance, 32);
    s->origin = origin;
}

void cs_subject_advance(struct cs_subject *s, const uint8_t prev_id[32],
                        const uint8_t provenance[32], uint8_t origin)
{
    sv1_copy(s->previous, prev_id, 32);
    s->sequence += 1;
    sv1_copy(s->provenance, provenance, 32);
    s->origin = origin;
}

static long find_intent(const struct cs_subject *s, const uint8_t id[32], uint32_t *ins)
{
    uint32_t i;
    for (i = 0; i < s->n_intents; i++) {
        int c = sv1_cmp_id(s->in[i].id, id);
        if (c == 0)
            return (long)i;
        if (c > 0)
            break;
    }
    if (ins)
        *ins = i;
    return -1;
}

const struct cs_intent *cs_subject_active(const struct cs_subject *s, uint32_t kind, uint64_t slot)
{
    for (uint32_t i = 0; i < s->n_intents; i++)
        if (s->in[i].state == CS_ACTIVE && s->in[i].kind == kind && s->in[i].payload[0] == slot)
            return &s->in[i];
    return 0;
}

int cs_subject_intend(struct cs_subject *s, uint32_t kind, const uint64_t payload[2],
                      uint8_t id_out[32], const char **why)
{
    struct cs_intent a;
    uint32_t ins = 0;
    if (!s || !payload)
        return fail(why, CC_E_ARG, "null argument");
    if (kind != CS_INTENT_GOAL_LATENCY)
        return fail(why, CC_E_ARG, "unknown intent kind");
    if (s->n_intents >= CS_MAX_INTENTS)
        return fail(why, CC_E_LIMIT, "too many standing intents");
    sv1_zero(&a, sizeof a);
    a.kind = kind;
    a.state = CS_ACTIVE;
    a.since = s->sequence;
    a.payload[0] = payload[0];
    a.payload[1] = payload[1];
    cs_intent_id(s->agent, kind, a.since, a.payload, a.id);
    if (find_intent(s, a.id, &ins) >= 0)
        return fail(why, CC_E_ARG, "intent already present");
    /* One active intent per slot: the old one is superseded by this one. */
    for (uint32_t i = 0; i < s->n_intents; i++) {
        struct cs_intent *o = &s->in[i];
        if (o->state == CS_ACTIVE && o->kind == kind && o->payload[0] == payload[0]) {
            o->state = CS_SUPERSEDED;
            sv1_copy(a.supersedes, o->id, 32);
            break;
        }
    }
    for (uint32_t i = s->n_intents; i > ins; i--)
        s->in[i] = s->in[i - 1];
    s->in[ins] = a;
    s->n_intents += 1;
    if (id_out)
        sv1_copy(id_out, a.id, 32);
    return CC_OK;
}

int cs_subject_retire(struct cs_subject *s, const uint8_t id[32], const char **why)
{
    long i;
    if (!s || !id)
        return fail(why, CC_E_ARG, "null argument");
    i = find_intent(s, id, 0);
    if (i < 0)
        return fail(why, CC_E_ARG, "intent absent");
    if (s->in[i].state != CS_ACTIVE)
        return fail(why, CC_E_ARG, "intent not active");
    s->in[i].state = CS_INACTIVE;
    return CC_OK;
}

int cs_subject_hold(struct cs_subject *s, const uint8_t digest[32], uint64_t record,
                    const char **why)
{
    uint32_t ins;
    if (!s || !digest)
        return fail(why, CC_E_ARG, "null argument");
    if (sv1_all_zero(digest, 32))
        return fail(why, CC_E_ARG, "zero knowledge digest");
    if (s->n_knowledge >= CS_MAX_KNOWLEDGE)
        return fail(why, CC_E_LIMIT, "too many knowledge references");
    for (ins = 0; ins < s->n_knowledge; ins++) {
        int c = sv1_cmp_id(s->kn[ins].digest, digest);
        if (c == 0)
            return fail(why, CC_E_ARG, "knowledge already held");
        if (c > 0)
            break;
    }
    for (uint32_t i = s->n_knowledge; i > ins; i--)
        s->kn[i] = s->kn[i - 1];
    sv1_copy(s->kn[ins].digest, digest, 32);
    s->kn[ins].record = record;
    s->kn[ins].since = s->sequence;
    s->n_knowledge += 1;
    return CC_OK;
}

void cs_subject_bind_cortex(struct cs_subject *s, const uint8_t lineage[32])
{
    sv1_copy(s->cortex, lineage, 32);
}

/* ---- resolve ---- */
static int map_cc(int rc)
{
    return rc == CC_E_LIMIT ? CR_LIMIT : rc == CC_E_ARG ? CR_E_ARG : CR_CORRUPT;
}

/* Pass 1: every kind-24 object of this Store into w->t (id, seq, previous),
 * each one decoded and checked against the resolved root. Pass 2: the chain
 * 1..n must be present exactly once each and linked by previous. The head is
 * re-read into out. */
int cs_resolve(const struct cr_source *src, struct cr_work *w, const struct cr_view *v,
               struct cs_subject *out, uint8_t out_id[32], const char **why, int *store_rc)
{
    uint32_t n, i, cnt = 0;
    uint64_t head_seq = 0;
    uint32_t head = 0;
    if (!src || !w || !v || !out || !out_id)
        return fail(why, CR_E_ARG, "null argument");
    n = src->count(src->ctx);
    for (i = 0; i < n; i++) {
        uint16_t kind = 0, version = 0;
        size_t len = 0;
        int rc;
        if ((rc = src->entry(src->ctx, i, &kind, &version))) {
            if (store_rc)
                *store_rc = rc;
            return fail(why, CR_STORE, "store entry failed");
        }
        if (kind != CC_KIND_SUBJECT)
            continue;
        if (version != CC_STORE_OBJECT_VERSION)
            return fail(why, CR_CORRUPT, "subject object with an unknown claim version");
        if ((rc = src->read(src->ctx, i, w->buf, sizeof w->buf, &len))) {
            if (store_rc)
                *store_rc = rc;
            return fail(why, CR_STORE, "store read failed");
        }
        if (len > sizeof w->buf)
            return fail(why, CR_LIMIT, "subject object exceeds the 16384-byte sealed Store cap");
        if ((rc = cs_subject_decode(w->buf, len, out, why)))
            return map_cc(rc);
#ifndef CS_MUTANT_ACCEPT_FOREIGN
        if (!sv1_equal(out->root, v->root_id, 32) || !sv1_equal(out->agent, v->root.agent_id, 32))
            return fail(why, CR_CORRUPT, "subject object belongs to another agent");
#endif
        if (cnt >= CR_TABLE_CAP)
            return fail(why, CR_LIMIT, "too many subject objects");
        if (cc_object_id(CC_KIND_SUBJECT, w->buf, len, w->t[cnt].id) != CC_OK)
            return fail(why, CR_E_ARG, "object id");
        w->t[cnt].seq = out->sequence;
        sv1_copy(w->t[cnt].previous, out->previous, 32);
        w->t[cnt].src = i;
        w->t[cnt].kind = kind;
        w->t[cnt].version = version;
        cnt++;
    }
    if (cnt == 0) {
        sv1_zero(out, sizeof *out);
        sv1_zero(out_id, 32);
        return CS_ABSENT;
    }
    /* Pass 2: exactly one object per sequence 1..cnt, each naming its predecessor. */
    for (uint64_t s = 1; s <= cnt; s++) {
        uint32_t at = cnt, found = 0;
        for (i = 0; i < cnt; i++)
            if (w->t[i].seq == s) {
                at = i;
                found++;
            }
#ifndef CS_MUTANT_ACCEPT_FORK
        if (found > 1)
            return fail(why, CR_CORRUPT, "subject chain fork");
#endif
        if (found == 0)
            return fail(why, CR_CORRUPT, "subject chain gap");
        if (s == 1) {
            if (!sv1_all_zero(w->t[at].previous, 32))
                return fail(why, CR_CORRUPT, "genesis subject names a previous object");
        } else {
            uint32_t prev = cnt;
            for (i = 0; i < cnt; i++)
                if (w->t[i].seq == s - 1)
                    prev = i;
            if (prev == cnt || !sv1_equal(w->t[at].previous, w->t[prev].id, 32))
                return fail(why, CR_CORRUPT, "subject chain link broken");
        }
        if (s > head_seq) {
            head_seq = s;
            head = at;
        }
    }
    {
        size_t len = 0;
        int rc;
        if ((rc = src->read(src->ctx, w->t[head].src, w->buf, sizeof w->buf, &len))) {
            if (store_rc)
                *store_rc = rc;
            return fail(why, CR_STORE, "store read failed");
        }
        if ((rc = cs_subject_decode(w->buf, len, out, why)))
            return map_cc(rc);
    }
    sv1_copy(out_id, w->t[head].id, 32);
    return CS_RESOLVED;
}

/* ---- commit ---- */
int cs_commit(const struct cr_source *src, const struct cr_sink *snk, struct cr_work *w,
              const struct cr_view *v, const struct cs_subject *s, uint8_t out_id[32],
              const char **why, int *store_rc)
{
    static struct cs_subject cur; /* scratch; the kernel style keeps big state static */
    uint8_t cur_id[32];
    size_t len = 0;
    int rc;
    struct cr_wobj obj;
    if (!src || !snk || !w || !v || !s || !out_id)
        return fail(why, CR_E_ARG, "null argument");
    if ((rc = cs_subject_validate(s, why)))
        return map_cc(rc);
    if (!sv1_equal(s->root, v->root_id, 32) || !sv1_equal(s->agent, v->root.agent_id, 32))
        return fail(why, CR_CORRUPT, "subject object belongs to another agent");
    rc = cs_resolve(src, w, v, &cur, cur_id, why, store_rc);
    if (rc == CS_ABSENT) {
        if (s->sequence != 1)
            return fail(why, CR_CORRUPT, "first subject object must have sequence 1");
    } else if (rc == CS_RESOLVED) {
        if (s->sequence != cur.sequence + 1 || !sv1_equal(s->previous, cur_id, 32))
            return fail(why, CR_CORRUPT, "subject object does not continue the resolved chain");
    } else {
        return rc;
    }
    if ((rc = cs_subject_encode(s, w->buf, sizeof w->buf, &len, why)))
        return map_cc(rc);
    obj.kind = CC_KIND_SUBJECT;
    obj.version = CC_STORE_OBJECT_VERSION;
    obj.bytes = w->buf;
    obj.len = len;
    if ((rc = snk->transact(snk->ctx, &obj, 1))) {
        if (store_rc)
            *store_rc = rc;
        return fail(why, CR_STORE, "store transaction failed");
    }
    if (cc_object_id(CC_KIND_SUBJECT, w->buf, len, out_id) != CC_OK)
        return fail(why, CR_E_ARG, "object id");
    return CS_RESOLVED;
}
