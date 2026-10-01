/* continuity_codec.c -- see continuity_codec.h. Oracle: continuity.rs =
 * crates/aienos-kernel/src/continuity.rs at aienos 4a116e5. Contract:
 * native/kernel/CONTINUITY_RECOVERY_CONTRACT.md (aienos#222) sections 1-2.
 * No allocation, no libc, no Store dependency. */
#include "continuity_codec.h"
#include "sha256.h" /* native/argus */

static const uint8_t MAGIC_ROOT[8] = {'A', 'I', 'E', 'N', 'R', 'O', 'O', 'T'};     /* :34 */
static const uint8_t MAGIC_MANIFEST[8] = {'A', 'I', 'E', 'N', 'M', 'A', 'N', 'I'}; /* :35 */
static const uint8_t MAGIC_BRANCHES[8] = {'A', 'I', 'E', 'N', 'B', 'R', 'A', 'N'}; /* :36 */
static const uint8_t MAGIC_WAL[8] = {'A', 'I', 'E', 'N', 'C', 'W', 'A', 'L'};      /* :37 */

/* Fixed body sizes (bytes after the 16-byte header). */
#define ROOT_BODY 96u          /* 32+16+32+8+1+7, continuity.rs:202 */
#define MANIFEST_FIXED 120u    /* 32+32+8+8+32+2+6, continuity.rs:268 */
#define STATE_FIXED 48u        /* 32+8+4+4, continuity.rs:394 */
#define WAL_FIXED 16u          /* 8+4+4, continuity.rs:533 */

/* K-1 reason text (PROPOSED; no Rust counterpart, contract 5.3). */
static const char WHY_CAP[] = "continuity object exceeds the 16384-byte sealed Store cap";

static int fail(const char **why, int cls, const char *w)
{
    if (why)
        *why = w;
    return cls;
}

/* ---- small byte helpers (no libc) ---- */
static void cp(uint8_t *d, const uint8_t *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        d[i] = s[i];
}
static int eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t x = 0;
    for (size_t i = 0; i < n; i++)
        x |= (uint8_t)(a[i] ^ b[i]);
    return x == 0;
}
static int is_zero(const uint8_t *a, size_t n)
{
    uint8_t x = 0;
    for (size_t i = 0; i < n; i++)
        x |= a[i];
    return x == 0;
}
/* Lexicographic order of two ids, as Rust [u8; 32] Ord (continuity.rs:361). */
static int cmp32(const uint8_t *a, const uint8_t *b)
{
    for (size_t i = 0; i < 32; i++)
        if (a[i] != b[i])
            return a[i] < b[i] ? -1 : 1;
    return 0;
}
static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}
static void put32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}
static void put64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}
static uint64_t get_le(const uint8_t *p, int n)
{
    uint64_t v = 0;
    for (int i = n - 1; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

/* ---- derivations ---- */
void cc_root_branch_id(const uint8_t agent[32], uint8_t out[32])
{
    static const char D[] = "AIENOS_ROOT_BRANCH_v1:"; /* continuity.rs:72 */
    sha256_ctx h;
    sha256_init(&h);
    sha256_update(&h, (const uint8_t *)D, sizeof D - 1);
    sha256_update(&h, agent, 32);
    sha256_final(&h, out);
}

void cc_child_branch_id(const uint8_t parent[32], uint64_t index, uint8_t out[32])
{
    static const char D[] = "AIENOS_CHILD_BRANCH_v1:"; /* continuity.rs:80 */
    uint8_t ix[8];
    for (int i = 0; i < 8; i++)
#ifdef CC_MUTANT_CHILD_INDEX_LE
        ix[i] = (uint8_t)(index >> (8 * i)); /* MUTANT MC-6: little-endian */
#else
        ix[i] = (uint8_t)(index >> (56 - 8 * i)); /* big-endian, continuity.rs:82 */
#endif
    sha256_ctx h;
    sha256_init(&h);
    sha256_update(&h, (const uint8_t *)D, sizeof D - 1);
    sha256_update(&h, parent, 32);
    sha256_update(&h, ix, 8);
    sha256_final(&h, out);
}

int cc_object_id(uint16_t kind, const uint8_t *bytes, size_t len, uint8_t out[32])
{
    /* store/v1.rs:27 OBJECT_DOMAIN = b"AIENOS-STORE-OBJECT-V1\0" (23 bytes). */
    static const char D[] = "AIENOS-STORE-OBJECT-V1";
    if (!bytes || !out || kind == 0 || len == 0) /* v1.rs:64 */
        return CC_E_ARG;
    if ((uint64_t)len > 67108864u) /* MAX_OBJECT_BYTES, v1.rs:15, :67 */
        return CC_E_ARG;
    uint8_t d[12];
    put16(d, kind);                     /* v1.rs:74 */
    put16(d + 2, CC_STORE_OBJECT_VERSION); /* v1.rs:75 */
    put64(d + 4, (uint64_t)len);        /* v1.rs:76 */
    sha256_ctx h;
    sha256_init(&h);
    sha256_update(&h, (const uint8_t *)D, sizeof D); /* includes the NUL */
    sha256_update(&h, d, sizeof d);
    sha256_update(&h, bytes, len);
    sha256_final(&h, out);
    return CC_OK;
}

/* ---- strict reader (continuity.rs:97-166) ---- */
struct rd {
    const uint8_t *b;
    size_t len, at;
    const char *why;
};

/* Reader::take (continuity.rs:123-132): the one bounds check. */
static int take(struct rd *r, size_t n, const uint8_t **p)
{
#ifndef CC_MUTANT_SKIP_TAKE_BOUND
    if (n > r->len - r->at) { /* r->at <= r->len always holds here */
        r->why = "truncated object";
        return CC_E_CORRUPT;
    }
#endif
    *p = r->b + r->at;
    r->at += n;
    return CC_OK;
}
static int rd_id(struct rd *r, uint8_t out[32])
{
    const uint8_t *p = 0;
    int e = take(r, 32, &p);
    if (!e)
        cp(out, p, 32);
    return e;
}
static int rd_uint(struct rd *r, int n, uint64_t *v)
{
    const uint8_t *p = 0;
    int e = take(r, (size_t)n, &p);
    if (!e)
        *v = get_le(p, n);
    return e;
}
/* Reader::zeros (continuity.rs:154-159). */
static int rd_zeros(struct rd *r, size_t n)
{
    const uint8_t *p = 0;
    int e = take(r, n, &p);
    if (e)
        return e;
#ifndef CC_MUTANT_ACCEPT_RESERVED
    if (!is_zero(p, n)) {
        r->why = "nonzero reserved";
        return CC_E_CORRUPT;
    }
#endif
    return CC_OK;
}
/* Reader::finish (continuity.rs:160-165). */
static int rd_finish(struct rd *r)
{
    if (r->at != r->len) {
        r->why = "trailing bytes";
        return CC_E_CORRUPT;
    }
    return CC_OK;
}

/* K-1 cap (PROPOSED) first, then Reader::open (continuity.rs:105-122). */
static int rd_open(struct rd *r, const uint8_t *in, size_t len, const uint8_t magic[8])
{
    const uint8_t *p = 0;
    uint64_t v = 0;
    int e;
    r->b = in;
    r->len = len;
    r->at = 0;
    r->why = 0;
    if (len > CC_MAX_OBJECT_BYTES) {
        r->why = WHY_CAP;
        return CC_E_LIMIT;
    }
    if ((e = take(r, 8, &p)))
        return e;
    if (!eq(p, magic, 8)) {
        r->why = "bad magic";
        return CC_E_CORRUPT;
    }
    if ((e = rd_uint(r, 2, &v)))
        return e;
    if (v != CC_FORMAT_VERSION) {
        r->why = "unsupported continuity format version";
        return CC_E_CORRUPT;
    }
    if ((e = rd_uint(r, 2, &v)))
        return e;
#ifndef CC_MUTANT_ACCEPT_RESERVED
    if (v != 0) {
        r->why = "nonzero header reserved";
        return CC_E_CORRUPT;
    }
#endif
    if ((e = rd_uint(r, 4, &v)))
        return e;
    if (v != (uint64_t)(len - CC_HEADER_BYTES)) {
        r->why = "body length mismatch";
        return CC_E_CORRUPT;
    }
    return CC_OK;
}

/* ---- writer: callers size-check first, so writes never overrun ---- */
struct wr {
    uint8_t *b;
    size_t at;
};
static void w_bytes(struct wr *w, const uint8_t *s, size_t n)
{
    cp(w->b + w->at, s, n);
    w->at += n;
}
static void w_zeros(struct wr *w, size_t n)
{
    for (size_t i = 0; i < n; i++)
        w->b[w->at + i] = 0;
    w->at += n;
}
static void w_u8(struct wr *w, uint8_t v)
{
    w->b[w->at++] = v;
}
static void w_u16(struct wr *w, uint16_t v)
{
    put16(w->b + w->at, v);
    w->at += 2;
}
static void w_u32(struct wr *w, uint32_t v)
{
    put32(w->b + w->at, v);
    w->at += 4;
}
static void w_u64(struct wr *w, uint64_t v)
{
    put64(w->b + w->at, v);
    w->at += 8;
}
/* header() (continuity.rs:90-95). */
static void w_header(struct wr *w, const uint8_t magic[8], size_t body)
{
    w_bytes(w, magic, 8);
    w_u16(w, CC_FORMAT_VERSION);
    w_u16(w, 0);
    w_u32(w, (uint32_t)body);
}

/* Common encoder prologue: K-1 cap (PROPOSED), then the caller's buffer. */
static int enc_begin(struct wr *w, uint8_t *out, size_t cap, size_t total,
                     const char **why)
{
    if (total > CC_MAX_OBJECT_BYTES)
        return fail(why, CC_E_LIMIT, WHY_CAP);
    if (!out || cap < total)
        return fail(why, CC_E_ARG, "output buffer too small");
    w->b = out;
    w->at = 0;
    return CC_OK;
}

/* ---- AgentRoot (continuity.rs:204-247) ---- */
int cc_root_encode(const struct cc_root *v, uint8_t *out, size_t cap, size_t *len,
                   const char **why)
{
    struct wr w;
    int e;
    if (!v || !len)
        return fail(why, CC_E_ARG, "null argument");
    *len = 0;
    /* ProvisionSource is a Rust enum (continuity.rs:186-191): no other value
     * exists there, so another value is a caller bug here. */
    if (v->source != CC_SOURCE_OPERATOR && v->source != CC_SOURCE_QUALIFICATION)
        return fail(why, CC_E_ARG, "unknown provisioning source");
    if ((e = enc_begin(&w, out, cap, CC_ROOT_BYTES, why)))
        return e;
    w_header(&w, MAGIC_ROOT, ROOT_BODY);   /* :207 */
    w_bytes(&w, v->agent_id, 32);          /* :208 */
    w_bytes(&w, v->store_uuid, 16);        /* :209 */
    w_bytes(&w, v->root_branch, 32);       /* :210 */
    w_u64(&w, v->provisioned_generation);  /* :211 */
    w_u8(&w, v->source);                   /* :212 */
    w_zeros(&w, 7);                        /* :213 */
    *len = w.at;
    return CC_OK;
}

int cc_root_decode(const uint8_t *in, size_t len, struct cc_root *v, const char **why)
{
    struct rd r;
    uint64_t x = 0;
    const uint8_t *p = 0;
    int e;
    uint8_t rb[32];
    if (!in || !v)
        return fail(why, CC_E_ARG, "null argument");
    if ((e = rd_open(&r, in, len, MAGIC_ROOT)) || (e = rd_id(&r, v->agent_id)) || /* :218-219 */
        (e = take(&r, 16, &p)))                                                   /* :221 */
        return fail(why, e, r.why);
    cp(v->store_uuid, p, 16);
    if ((e = rd_id(&r, v->root_branch)) || (e = rd_uint(&r, 8, &x))) /* :222-223 */
        return fail(why, e, r.why);
    v->provisioned_generation = x;
    if ((e = rd_uint(&r, 1, &x))) /* :224 */
        return fail(why, e, r.why);
    if (x != CC_SOURCE_OPERATOR && x != CC_SOURCE_QUALIFICATION) /* :224-228 */
        return fail(why, CC_E_CORRUPT, "unknown provisioning source");
    v->source = (uint8_t)x;
    if ((e = rd_zeros(&r, 7)) || (e = rd_finish(&r))) /* :229-230 */
        return fail(why, e, r.why);
    if (is_zero(v->agent_id, 32)) /* :231-233 */
        return fail(why, CC_E_CORRUPT, "zero agent id");
    cc_root_branch_id(v->agent_id, rb);
    if (!eq(rb, v->root_branch, 32)) /* :234-238 */
        return fail(why, CC_E_CORRUPT, "root branch does not derive from agent");
    return CC_OK;
}

/* ---- ContinuityManifest (continuity.rs:263-315) ---- */
int cc_manifest_encode(const struct cc_manifest *v, uint8_t *out, size_t cap, size_t *len,
                       const char **why)
{
    struct wr w;
    int e;
    if (!v || !len)
        return fail(why, CC_E_ARG, "null argument");
    *len = 0;
    if (v->n_wal > CC_MAX_WAL_SEGMENTS) /* :265-267 */
        return fail(why, CC_E_LIMIT, "too many cortex WAL segments");
    size_t body = MANIFEST_FIXED + 32u * v->n_wal; /* :268 */
    if ((e = enc_begin(&w, out, cap, CC_HEADER_BYTES + body, why)))
        return e;
    w_header(&w, MAGIC_MANIFEST, body);   /* :270 */
    w_bytes(&w, v->root, 32);             /* :271 */
    w_bytes(&w, v->previous, 32);         /* :272 (None = zero, :177-179) */
    w_u64(&w, v->sequence);               /* :273 */
    w_u64(&w, v->incarnation);            /* :274 */
    w_bytes(&w, v->agent_state, 32);      /* :275 */
    w_u16(&w, (uint16_t)v->n_wal);        /* :276 */
    w_zeros(&w, 6);                       /* :277 */
    for (uint32_t i = 0; i < v->n_wal; i++)
        w_bytes(&w, v->wal[i], 32);       /* :278-280 */
    *len = w.at;
    return CC_OK;
}

int cc_manifest_decode(const uint8_t *in, size_t len, struct cc_manifest *v, const char **why)
{
    struct rd r;
    uint64_t x = 0;
    int e;
    if (!in || !v)
        return fail(why, CC_E_ARG, "null argument");
    if ((e = rd_open(&r, in, len, MAGIC_MANIFEST)) || (e = rd_id(&r, v->root)) || /* :285-286 */
        (e = rd_id(&r, v->previous)) || (e = rd_uint(&r, 8, &v->sequence)) ||     /* :287-288 */
        (e = rd_uint(&r, 8, &v->incarnation)) || (e = rd_id(&r, v->agent_state)) || /* :289-290 */
        (e = rd_uint(&r, 2, &x)) || (e = rd_zeros(&r, 6)))                       /* :291-292 */
        return fail(why, e, r.why);
    if (x > CC_MAX_WAL_SEGMENTS) /* :293-295 */
        return fail(why, CC_E_CORRUPT, "too many cortex WAL segments");
    v->n_wal = (uint32_t)x;
    for (uint32_t i = 0; i < v->n_wal; i++)
        if ((e = rd_id(&r, v->wal[i]))) /* :297-299 */
            return fail(why, e, r.why);
    if ((e = rd_finish(&r))) /* :300 */
        return fail(why, e, r.why);
    /* :301-305: sequence 0, or "sequence 1" differs from "no previous". */
    if (v->sequence == 0 || (v->sequence == 1) != is_zero(v->previous, 32))
        return fail(why, CC_E_CORRUPT, "manifest sequence/previous mismatch");
    return CC_OK;
}

/* ---- AgentState branch table (continuity.rs:342-482) ---- */
/* binary_search_by on the sorted ids (continuity.rs:358-362): index of id, or
 * -1 with *ins = insertion point. */
static long find_branch(const struct cc_state *s, const uint8_t id[32], uint32_t *ins)
{
    uint32_t lo = 0, hi = s->n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        int c = cmp32(s->br[mid].id, id);
        if (c == 0)
            return (long)mid;
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (ins)
        *ins = lo;
    return -1;
}

void cc_state_genesis(struct cc_state *s, const uint8_t agent[32], uint64_t written_at)
{
    cp(s->agent_id, agent, 32);
    s->written_at = written_at;
    s->n = 1;
    cc_root_branch_id(agent, s->br[0].id);
    for (int i = 0; i < 32; i++)
        s->br[0].parent[i] = 0;
    s->br[0].depth = 0;
    s->br[0].forks = 0;
}

int cc_state_validate(const struct cc_state *s, const char **why)
{
    const char *bad = 0;
    if (!s)
        return fail(why, CC_E_ARG, "null argument");
    if (s->n == 0 || s->n > CC_MAX_BRANCHES) /* :449-451 */
        return fail(why, CC_E_CORRUPT, "branch count out of range");
    for (uint32_t i = 0; i + 1 < s->n; i++) /* :452-454 */
        if (cmp32(s->br[i].id, s->br[i + 1].id) >= 0)
            return fail(why, CC_E_CORRUPT, "branches not strictly sorted");
    uint8_t root[32], cid[32];
    cc_root_branch_id(s->agent_id, root); /* :455 */
    uint32_t roots = 0;
    uint64_t children = 0;
    for (uint32_t i = 0; i < s->n && !bad; i++) {
        const struct cc_branch *b = &s->br[i];
        if (is_zero(b->parent, 32)) { /* :460-465 */
            if (!eq(b->id, root, 32) || b->depth != 0)
                bad = "unexpected root branch";
            roots++;
            continue;
        }
        long pi = find_branch(s, b->parent, 0); /* :467 */
        if (pi < 0) {
            bad = "parent branch is absent";
            break;
        }
        const struct cc_branch *p = &s->br[pi];
        /* :468: any index in 0..parent.forks derives this id. The scan is
         * capped at CC_MAX_BRANCHES: a table that passes the fork-sum check
         * below has every forks <= 255, so the cap changes no accept/refuse
         * outcome, only bounds the work (Rust scans up to forks, which an
         * input controls; see the PR's oracle notes). */
        uint64_t lim = p->forks < CC_MAX_BRANCHES ? p->forks : CC_MAX_BRANCHES;
        int index_ok = 0;
        for (uint64_t k = 0; k < lim && !index_ok; k++) {
            cc_child_branch_id(b->parent, k, cid);
            index_ok = eq(cid, b->id, 32);
        }
        if (!index_ok || p->depth == UINT32_MAX || b->depth != p->depth + 1) /* :469-471 */
            bad = "branch lineage is inconsistent";
        children++;
    }
    if (bad)
        return fail(why, CC_E_CORRUPT, bad);
    /* :476-479: sum of forks == number of children, exactly one root. The
     * sum is checked: an overflowing sum can never equal children (<= 255). */
    uint64_t forks = 0;
    int over = 0;
    for (uint32_t i = 0; i < s->n; i++) {
        if (s->br[i].forks > UINT64_MAX - forks)
            over = 1;
        else
            forks += s->br[i].forks;
    }
    if (roots != 1 || over || forks != children)
        return fail(why, CC_E_CORRUPT, "fork indexes are not contiguous");
    return CC_OK;
}

int cc_state_fork(struct cc_state *s, const uint8_t parent[32], uint8_t child_out[32],
                  const char **why)
{
    if (!s || !parent || !child_out)
        return fail(why, CC_E_ARG, "null argument");
    if (s->n >= CC_MAX_BRANCHES) /* :366-368 */
        return fail(why, CC_E_LIMIT, "too many branches");
    long i = find_branch(s, parent, 0); /* :369-372 */
    if (i < 0)
        return fail(why, CC_E_CORRUPT, "fork parent is absent");
    uint64_t index = s->br[i].forks; /* :373 */
    uint32_t depth = s->br[i].depth;
    struct cc_branch c;
    cc_child_branch_id(parent, index, c.id); /* :375 */
    cp(c.parent, parent, 32);
    if (depth == UINT32_MAX) /* :377-379 */
        return fail(why, CC_E_LIMIT, "branch depth");
    c.depth = depth + 1;
    c.forks = 0;
    /* :382: the parent's fork count advances before the collision check, as
     * in Rust (a collision leaves it advanced and returns Corrupt). */
    s->br[i].forks = index + 1;
    uint32_t at = 0;
    if (find_branch(s, c.id, &at) >= 0) /* :383-387 */
        return fail(why, CC_E_CORRUPT, "child branch id collision");
    for (uint32_t k = s->n; k > at; k--) /* :388 insert keeps order */
        s->br[k] = s->br[k - 1];
    s->br[at] = c;
    s->n++;
    cp(child_out, c.id, 32);
    return CC_OK;
}

int cc_state_encode(const struct cc_state *v, uint8_t *out, size_t cap, size_t *len,
                    const char **why)
{
    struct wr w;
    int e;
    if (!v || !len)
        return fail(why, CC_E_ARG, "null argument");
    *len = 0;
    if ((e = cc_state_validate(v, why))) /* :393 */
        return e;
    size_t body = STATE_FIXED + (size_t)CC_BRANCH_BYTES * v->n; /* :394 */
    if ((e = enc_begin(&w, out, cap, CC_HEADER_BYTES + body, why)))
        return e;
    w_header(&w, MAGIC_BRANCHES, body); /* :396 */
    w_bytes(&w, v->agent_id, 32);       /* :397 */
    w_u64(&w, v->written_at);           /* :398 */
    w_u32(&w, v->n);                    /* :399 */
    w_zeros(&w, 4);                     /* :400 */
    for (uint32_t i = 0; i < v->n; i++) {
        w_bytes(&w, v->br[i].id, 32);     /* :402 */
        w_bytes(&w, v->br[i].parent, 32); /* :403 */
        w_u32(&w, v->br[i].depth);        /* :404 */
        w_zeros(&w, 4);                   /* :405 */
        w_u64(&w, v->br[i].forks);        /* :406 */
    }
    *len = w.at;
    return CC_OK;
}

int cc_state_decode(const uint8_t *in, size_t len, struct cc_state *v, const char **why)
{
    struct rd r;
    uint64_t x = 0;
    int e;
    if (!in || !v)
        return fail(why, CC_E_ARG, "null argument");
    if ((e = rd_open(&r, in, len, MAGIC_BRANCHES)) || (e = rd_id(&r, v->agent_id)) || /* :412-413 */
        (e = rd_uint(&r, 8, &v->written_at)) || (e = rd_uint(&r, 4, &x)) ||           /* :414-415 */
        (e = rd_zeros(&r, 4)))                                                         /* :416 */
        return fail(why, e, r.why);
    if (x == 0 || x > CC_MAX_BRANCHES) /* :417-419 */
        return fail(why, CC_E_CORRUPT, "branch count out of range");
    v->n = (uint32_t)x;
    for (uint32_t i = 0; i < v->n; i++) {
        struct cc_branch *b = &v->br[i];
        uint64_t d = 0;
        if ((e = rd_id(&r, b->id)) || (e = rd_id(&r, b->parent)) || /* :422-423 */
            (e = rd_uint(&r, 4, &d)) || (e = rd_zeros(&r, 4)) ||    /* :424-425 */
            (e = rd_uint(&r, 8, &b->forks)))                        /* :426 */
            return fail(why, e, r.why);
        b->depth = (uint32_t)d;
    }
    if ((e = rd_finish(&r))) /* :434 */
        return fail(why, e, r.why);
    return cc_state_validate(v, why); /* :440 */
}

/* ---- CortexWalSegment (continuity.rs:527-582) ---- */
int cc_wal_encode(const struct cc_wal *v, uint8_t *out, size_t cap, size_t *len,
                  const char **why)
{
    struct wr w;
    int e;
    if (!v || !len)
        return fail(why, CC_E_ARG, "null argument");
    *len = 0;
    if (v->n == 0 || v->n > CC_MAX_WAL_RECORDS) /* :529-531 */
        return fail(why, CC_E_LIMIT, "WAL segment record count");
    size_t body = WAL_FIXED; /* :532 */
    for (uint32_t i = 0; i < v->n; i++) {
        const struct cc_record *rec = &v->rec[i];
        if (rec->len == 0 || rec->len > CC_MAX_STATEMENT_BYTES) /* :534-536 */
            return fail(why, CC_E_LIMIT, "statement length");
        /* Epistemic is a Rust enum (:490-511): other values are a caller bug. */
        if (rec->status < CC_EPI_DIRECT_OBSERVATION || rec->status > CC_EPI_OPERATOR_DECISION ||
            !rec->statement)
            return fail(why, CC_E_ARG, "bad record");
        body += CC_WAL_RECORD_FIXED + rec->len; /* :537 */
    }
    uint32_t n = v->n;
#ifdef CC_MUTANT_TRUNCATE_AT_CAP
    /* MUTANT MC-11: silently drop records to fit the K-1 cap. */
    while (n > 1 && CC_HEADER_BYTES + body > CC_MAX_OBJECT_BYTES) {
        n--;
        body -= CC_WAL_RECORD_FIXED + v->rec[n].len;
    }
#endif
    if ((e = enc_begin(&w, out, cap, CC_HEADER_BYTES + body, why)))
        return e;
    w_header(&w, MAGIC_WAL, body); /* :540 */
    w_u64(&w, v->sequence);        /* :541 */
    w_u32(&w, n);                  /* :542 */
    w_zeros(&w, 4);                /* :543 */
    for (uint32_t i = 0; i < n; i++) {
        const struct cc_record *rec = &v->rec[i];
        w_u8(&w, rec->status);              /* :545 */
        w_u8(&w, 0);                        /* :546 */
        w_u16(&w, rec->len);                /* :547 */
        w_bytes(&w, rec->evidence_hash, 32); /* :548 */
        w_bytes(&w, rec->statement, rec->len); /* :549 */
    }
    *len = w.at;
    return CC_OK;
}

int cc_wal_decode(const uint8_t *in, size_t len, struct cc_wal *v, const char **why)
{
    struct rd r;
    uint64_t x = 0;
    int e;
    if (!in || !v)
        return fail(why, CC_E_ARG, "null argument");
    if ((e = rd_open(&r, in, len, MAGIC_WAL)) || (e = rd_uint(&r, 8, &v->sequence)) || /* :555-556 */
        (e = rd_uint(&r, 4, &x)) || (e = rd_zeros(&r, 4)))                              /* :557-558 */
        return fail(why, e, r.why);
    if (x == 0 || x > CC_MAX_WAL_RECORDS) /* :559-561 */
        return fail(why, CC_E_CORRUPT, "WAL segment record count");
    v->n = (uint32_t)x;
    for (uint32_t i = 0; i < v->n; i++) {
        struct cc_record *rec = &v->rec[i];
        uint64_t st = 0, l = 0;
        const uint8_t *p = 0;
        if ((e = rd_uint(&r, 1, &st))) /* :564 */
            return fail(why, e, r.why);
        if (st < CC_EPI_DIRECT_OBSERVATION || st > CC_EPI_OPERATOR_DECISION) /* :564-565 */
            return fail(why, CC_E_CORRUPT, "unknown epistemic status");
        if ((e = rd_zeros(&r, 1)) || (e = rd_uint(&r, 2, &l))) /* :566-567 */
            return fail(why, e, r.why);
        if (l == 0 || l > CC_MAX_STATEMENT_BYTES) /* :568-570 */
            return fail(why, CC_E_CORRUPT, "statement length");
        if ((e = rd_id(&r, rec->evidence_hash)) || (e = take(&r, (size_t)l, &p))) /* :571-572 */
            return fail(why, e, r.why);
        rec->status = (uint8_t)st;
        rec->len = (uint16_t)l;
        rec->statement = p;
    }
    if ((e = rd_finish(&r))) /* :579 */
        return fail(why, e, r.why);
    return CC_OK;
}
