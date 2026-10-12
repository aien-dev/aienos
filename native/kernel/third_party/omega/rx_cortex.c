/*
 * rx_cortex.c -- Cortex, canonical (M20). See rx_cortex.h.
 */
#include "rx_cortex.h"

#include "sha256.h"

#include <string.h>

/* Allocation hooks: a freestanding host names a config header through
 * CX_CONFIG_H that defines CX_MALLOC(n), CX_REALLOC(p, n) and CX_FREE(p). */
#ifdef CX_CONFIG_H
#include CX_CONFIG_H
#endif
#ifndef CX_MALLOC
#include <stdlib.h>
#define CX_MALLOC(n) malloc(n)
#define CX_REALLOC(p, n) realloc((p), (n))
#define CX_FREE(p) free(p)
#endif

#ifndef CX_NO_POSIX
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

static void put_u64(sha256_ctx *c, uint64_t v) {
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (8 * i));
    sha256_update(c, b, 8);
}

void cx_digest(const CxObject *o, const uint64_t *payload, uint8_t out[32]) {
    static const uint8_t domain[] = "AIEN.CORTEX.OBJECT.V1";
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, domain, sizeof domain - 1);
    put_u64(&c, o->id);
    put_u64(&c, ((uint64_t)o->cls << 32) | o->kind);
    put_u64(&c, o->subject);
    put_u64(&c, o->t);
    put_u64(&c, o->generation);
    put_u64(&c, ((uint64_t)o->branch << 32) | o->protect);
    put_u64(&c, o->tag);
    for (uint32_t i = 0; i < CX_LINKS; i++) put_u64(&c, o->links[i]);
    put_u64(&c, o->n);
    for (uint32_t i = 0; i < o->n; i++) put_u64(&c, payload[i]);
    sha256_final(&c, out);
}

static void chain_step(uint8_t chain[32], const uint8_t digest[32]) {
    uint8_t buf[64];
    memcpy(buf, chain, 32);
    memcpy(buf + 32, digest, 32);
    sha256_hash(buf, sizeof buf, chain);
}

int cx_init(CxStore *s, uint64_t n_subjects) {
    memset(s, 0, sizeof(*s));
    size_t nb = (size_t)(n_subjects ? n_subjects : 1) * sizeof(CxIdList);
    s->by_subject = CX_MALLOC(nb);
    if (!s->by_subject) return CX_ERR_NOMEM;
    memset(s->by_subject, 0, nb);
    s->n_subjects = n_subjects;
    return CX_OK;
}

void cx_free(CxStore *s) {
    for (uint64_t i = 0; i < s->n_subjects && s->by_subject; i++) CX_FREE(s->by_subject[i].ids);
    CX_FREE(s->by_subject);
    CX_FREE(s->obj);
    CX_FREE(s->arena);
    if (s->jops) s->jops->close(s->jctx, s->jh);   /* closing drops the writer lock */
    memset(s, 0, sizeof(*s));
}

void cx_close(CxStore *s) { cx_free(s); }

static int grow(void **p, uint64_t *cap, uint64_t need, size_t elem) {
    if (need <= *cap) return 0;
    uint64_t c = *cap ? *cap : 1024;
    while (c < need) c *= 2;
    void *q = CX_REALLOC(*p, c * elem);
    if (!q) return -1;
    *p = q;
    *cap = c;
    return 0;
}

/* ---- journal encoding ---------------------------------------------------- */

#define CX_J_MAGIC   0x0131584e45494141ull   /* journal magic */
#define CX_J_VERSION 1ull
#define CX_J_HDR_WORDS 4u
#define CX_R_MAGIC   0x4443524f43584355ull   /* record marker */
#define CX_R_FIXED   13u                     /* marker + 12 header words */
#define CX_R_DIGEST  4u

static void le_put(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static uint64_t le_get(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

/* Encode one object as a journal record into a fresh buffer. */
static uint8_t *encode_record(const CxObject *o, const uint64_t *payload, size_t *out_len) {
    size_t words = CX_R_FIXED + o->n + CX_R_DIGEST;
    uint8_t *b = CX_MALLOC(words * 8);
    if (!b) return NULL;
    uint64_t w[CX_R_FIXED] = {
        CX_R_MAGIC, o->id, ((uint64_t)o->cls << 32) | o->kind, o->subject, o->t,
        o->generation, ((uint64_t)o->branch << 32) | o->protect, o->tag,
        o->links[0], o->links[1], o->links[2], o->links[3], o->n
    };
    size_t k = 0;
    for (uint32_t i = 0; i < CX_R_FIXED; i++, k += 8) le_put(b + k, w[i]);
    for (uint32_t i = 0; i < o->n; i++, k += 8) le_put(b + k, payload[i]);
    memcpy(b + k, o->digest, 32);
    *out_len = words * 8;
    return b;
}

/* ---- append -------------------------------------------------------------- */

/* Append into memory. `expect_id` nonzero: replay, the id must match. */
static int append_mem(CxStore *s, const CxHeader *h, const uint64_t *payload, uint32_t n,
                      uint64_t expect_id, uint64_t *out_id) {
    if (!h || h->cls == 0 || h->cls >= CX_CLASS_END || h->subject >= s->n_subjects ||
        (n && !payload))
        return CX_ERR_ARG;
    if (expect_id && expect_id != s->n + 1) return CX_ERR_FORMAT;
    CxIdList *l = &s->by_subject[h->subject];
    if (l->n && s->obj[l->ids[l->n - 1] - 1].t > h->t) return CX_ERR_ORDER;
    if (grow((void **)&s->obj, &s->cap, s->n + 1, sizeof(CxObject)) ||
        grow((void **)&s->arena, &s->arena_cap, s->arena_n + n, sizeof(uint64_t)))
        return CX_ERR_NOMEM;
    if (l->n == l->cap) {
        uint32_t c = l->cap ? l->cap * 2 : 64;
        uint64_t *q = CX_REALLOC(l->ids, (size_t)c * sizeof(uint64_t));
        if (!q) return CX_ERR_NOMEM;
        l->ids = q;
        l->cap = c;
    }
    CxObject *o = &s->obj[s->n];
    memset(o, 0, sizeof(*o));
    o->id = s->n + 1;
    o->cls = h->cls;
    o->kind = h->kind;
    o->subject = h->subject;
    o->t = h->t;
    o->generation = h->generation;
    o->branch = h->branch;
    o->protect = h->protect & CX_PROT_ALL;
    o->tag = h->tag;
    memcpy(o->links, h->links, sizeof o->links);
    o->n = n;
    o->off = s->arena_n;
    if (n) memcpy(s->arena + s->arena_n, payload, (size_t)n * sizeof(uint64_t));
    s->arena_n += n;
    cx_digest(o, s->arena + o->off, o->digest);
    chain_step(s->chain, o->digest);
    l->ids[l->n++] = o->id;
    s->n++;
    if (out_id) *out_id = o->id;
    return CX_OK;
}

/* Undo the newest in-memory append (journal write failed). */
static void unappend_mem(CxStore *s, const uint8_t prev_chain[32]) {
    CxObject *o = &s->obj[s->n - 1];
    s->by_subject[o->subject].n--;
    s->arena_n = o->off;
    s->n--;
    memcpy(s->chain, prev_chain, 32);
}

int cx_append_as(CxStore *s, uint64_t token, const CxHeader *h, const uint64_t *payload,
                 uint32_t n, uint64_t *out_id) {
    if (!s) return CX_ERR_ARG;
    if (s->writer != token) return CX_ERR_WRITER;
    if (s->open_flags & CX_OPEN_READONLY) return CX_ERR_WRITER;
    uint8_t prev[32];
    memcpy(prev, s->chain, 32);
    uint64_t id = 0;
    int rc = append_mem(s, h, payload, n, 0, &id);
    if (rc != CX_OK) return rc;
    if (s->jops) {
        const CxObject *o = &s->obj[id - 1];
        size_t len = 0;
        uint8_t *rec = encode_record(o, s->arena + o->off, &len);
        if (!rec) {
            unappend_mem(s, prev);
            return CX_ERR_NOMEM;
        }
        /* The backend appends all of the record or none of it; memory never
         * runs ahead of the journal. */
        int rc2 = s->jops->append(s->jctx, s->jh, rec, len, (s->open_flags & CX_OPEN_SYNC) != 0);
        CX_FREE(rec);
        if (rc2 != CX_OK) {
            unappend_mem(s, prev);
            return rc2;
        }
    }
    if (out_id) *out_id = id;
    return CX_OK;
}

int cx_append(CxStore *s, const CxHeader *h, const uint64_t *payload, uint32_t n, uint64_t *out_id) {
    return cx_append_as(s, 0, h, payload, n, out_id);
}

int cx_claim_writer(CxStore *s, uint64_t token) {
    if (!s || token == 0) return CX_ERR_ARG;
    if (s->open_flags & CX_OPEN_READONLY) return CX_ERR_WRITER;
    if (s->writer && s->writer != token) return CX_ERR_WRITER;
    s->writer = token;
    return CX_OK;
}

void cx_release_writer(CxStore *s, uint64_t token) {
    if (s && token && s->writer == token) s->writer = 0;
}

/* ---- journal open / replay ----------------------------------------------- */

static int read_journal(const CxJournalOps *ops, void *ctx, void *h, uint8_t **out, size_t *len) {
    size_t n = 0;
    int rc = ops->size(ctx, h, &n);
    if (rc != CX_OK) return rc;
    uint8_t *b = CX_MALLOC(n ? n : 1);
    if (!b) return CX_ERR_NOMEM;
    if (n) {
        rc = ops->read(ctx, h, 0, b, n);
        if (rc != CX_OK) { CX_FREE(b); return rc; }
    }
    *out = b;
    *len = n;
    return CX_OK;
}

static int replay(CxStore *s, const uint8_t *b, size_t len, size_t *good_end) {
    size_t p = CX_J_HDR_WORDS * 8;
    *good_end = p;
    uint64_t *payload = NULL;
    uint32_t payload_cap = 0;
    int rc = CX_OK;
    while (p < len) {
        if (len - p < CX_R_FIXED * 8) { rc = CX_ERR_TORN; break; }
        uint64_t w[CX_R_FIXED];
        for (uint32_t i = 0; i < CX_R_FIXED; i++) w[i] = le_get(b + p + 8 * i);
        if (w[0] != CX_R_MAGIC || w[12] > UINT32_MAX) { rc = CX_ERR_FORMAT; break; }
        uint32_t n = (uint32_t)w[12];
        size_t rec = ((size_t)CX_R_FIXED + n + CX_R_DIGEST) * 8;
        if (len - p < rec) { rc = CX_ERR_TORN; break; }
        if (n > payload_cap) {
            uint64_t *q = CX_REALLOC(payload, (size_t)n * sizeof(uint64_t));
            if (!q) { rc = CX_ERR_NOMEM; break; }
            payload = q;
            payload_cap = n;
        }
        for (uint32_t i = 0; i < n; i++) payload[i] = le_get(b + p + 8 * (CX_R_FIXED + i));
        CxHeader h;
        memset(&h, 0, sizeof h);
        h.cls = (uint32_t)(w[2] >> 32);
        h.kind = (uint32_t)w[2];
        h.subject = w[3];
        h.t = w[4];
        h.generation = w[5];
        h.branch = (uint32_t)(w[6] >> 32);
        h.protect = (uint32_t)w[6];
        h.tag = w[7];
        for (uint32_t i = 0; i < CX_LINKS; i++) h.links[i] = w[8 + i];
        uint64_t id = 0;
        rc = append_mem(s, &h, payload, n, w[1], &id);
        if (rc != CX_OK) break;
        if (memcmp(s->obj[id - 1].digest, b + p + 8 * (CX_R_FIXED + n), 32) != 0) {
            rc = CX_ERR_DIGEST;
            break;
        }
        p += rec;
        *good_end = p;
    }
    CX_FREE(payload);
    return rc;
}

/* The single integrity seam: see the guarantee in rx_cortex.h. */
int cx_open_with(CxStore *s, const CxJournalOps *ops, void *ctx, const char *name,
                 uint64_t n_subjects, uint32_t flags) {
    if (!s || !ops || !name || !ops->open || !ops->size || !ops->read || !ops->append ||
        !ops->truncate || !ops->close)
        return CX_ERR_ARG;
    int ro = (flags & CX_OPEN_READONLY) != 0;
    void *jh = NULL;
    int rc = ops->open(ctx, name, ro, &jh);
    if (rc != CX_OK) return rc;
    uint8_t *b = NULL;
    size_t len = 0;
    rc = read_journal(ops, ctx, jh, &b, &len);
    if (rc != CX_OK) { ops->close(ctx, jh); return rc; }
    if (len == 0) {
        if (ro || n_subjects == 0) { CX_FREE(b); ops->close(ctx, jh); return CX_ERR_FORMAT; }
        uint8_t h[CX_J_HDR_WORDS * 8] = { 0 };
        le_put(h, CX_J_MAGIC);
        le_put(h + 8, CX_J_VERSION);
        le_put(h + 16, n_subjects);
        le_put(h + 24, 0);   /* reserved: canonical machine identity (M20 A1) */
        rc = ops->append(ctx, jh, h, sizeof h, 1);
        if (rc != CX_OK) { CX_FREE(b); ops->close(ctx, jh); return rc; }
    } else {
        if (len < CX_J_HDR_WORDS * 8 || le_get(b) != CX_J_MAGIC || le_get(b + 8) != CX_J_VERSION) {
            CX_FREE(b); ops->close(ctx, jh); return CX_ERR_FORMAT;
        }
        uint64_t file_subjects = le_get(b + 16);
        if (n_subjects && n_subjects != file_subjects) {
            CX_FREE(b); ops->close(ctx, jh); return CX_ERR_FORMAT;
        }
        n_subjects = file_subjects;
    }
    rc = cx_init(s, n_subjects);
    if (rc != CX_OK) { CX_FREE(b); ops->close(ctx, jh); return rc; }
    if (len) {
        size_t good = 0;
        rc = replay(s, b, len, &good);
        if (rc == CX_ERR_TORN && !ro && (flags & CX_OPEN_REPAIR_TAIL)) {
            /* Only an incomplete trailing record is dropped. A complete record
             * whose digest differs is never repaired. */
            rc = ops->truncate(ctx, jh, good);
        }
    }
    CX_FREE(b);
    if (rc != CX_OK) {
        ops->close(ctx, jh);
        cx_free(s);
        return rc;
    }
    s->jops = ops;
    s->jctx = ctx;
    s->jh = jh;
    s->open_flags = flags;
    return CX_OK;
}

#ifndef CX_NO_POSIX
/* ---- the file backend ---------------------------------------------------- */

static int write_all(int fd, const uint8_t *b, size_t n) {
    while (n) {
        ssize_t w = write(fd, b, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        b += w;
        n -= (size_t)w;
    }
    return 0;
}

static int jp_open(void *ctx, const char *name, int ro, void **h) {
    (void)ctx;
    int fd = open(name, ro ? O_RDONLY | O_CLOEXEC : O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0) return CX_ERR_IO;
    if (!ro && flock(fd, LOCK_EX | LOCK_NB) != 0) {
        int e = errno;
        close(fd);
        return e == EWOULDBLOCK ? CX_ERR_WRITER : CX_ERR_IO;
    }
    *h = (void *)(intptr_t)fd;
    return CX_OK;
}

static int jp_size(void *ctx, void *h, size_t *len) {
    (void)ctx;
    struct stat st;
    if (fstat((int)(intptr_t)h, &st) != 0) return CX_ERR_IO;
    *len = (size_t)st.st_size;
    return CX_OK;
}

static int jp_read(void *ctx, void *h, size_t off, uint8_t *out, size_t n) {
    (void)ctx;
    int fd = (int)(intptr_t)h;
    size_t got = 0;
    while (got < n) {
        ssize_t r = pread(fd, out + got, n - got, (off_t)(off + got));
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return CX_ERR_IO;
        got += (size_t)r;
    }
    return CX_OK;
}

static int jp_append(void *ctx, void *h, const uint8_t *b, size_t n, int sync) {
    (void)ctx;
    int fd = (int)(intptr_t)h;
    off_t end = lseek(fd, 0, SEEK_END);
    if (end < 0) return CX_ERR_IO;
    if (write_all(fd, b, n) != 0 || (sync && fdatasync(fd) != 0)) {
        /* Never leave a partial record behind. */
        if (ftruncate(fd, end) != 0) { /* reopen will see a torn tail */ }
        return CX_ERR_IO;
    }
    return CX_OK;
}

static int jp_truncate(void *ctx, void *h, size_t len) {
    (void)ctx;
    int fd = (int)(intptr_t)h;
    return ftruncate(fd, (off_t)len) == 0 && fdatasync(fd) == 0 ? CX_OK : CX_ERR_IO;
}

static void jp_close(void *ctx, void *h) {
    (void)ctx;
    close((int)(intptr_t)h);   /* closing drops the flock */
}

const CxJournalOps cx_journal_posix = { jp_open, jp_size, jp_read, jp_append, jp_truncate, jp_close };

int cx_open(CxStore *s, const char *path, uint64_t n_subjects, uint32_t flags) {
    return cx_open_with(s, &cx_journal_posix, NULL, path, n_subjects, flags);
}
#endif /* !CX_NO_POSIX */

/* ---- read ---------------------------------------------------------------- */

const CxObject *cx_get(const CxStore *s, uint64_t id) {
    return id >= 1 && id <= s->n ? &s->obj[id - 1] : NULL;
}

const uint64_t *cx_payload(const CxStore *s, const CxObject *o) { return s->arena + o->off; }

int cx_verify(const CxStore *s, uint64_t id) {
    const CxObject *o = cx_get(s, id);
    if (!o) return CX_ERR_ARG;
    uint8_t d[32];
    cx_digest(o, cx_payload(s, o), d);
    return memcmp(d, o->digest, 32) == 0 ? CX_OK : CX_ERR_DIGEST;
}

int cx_verify_chain(const CxStore *s) {
    uint8_t chain[32] = { 0 };
    for (uint64_t i = 0; i < s->n; i++) {
        uint8_t d[32];
        cx_digest(&s->obj[i], cx_payload(s, &s->obj[i]), d);
        if (memcmp(d, s->obj[i].digest, 32) != 0) return CX_ERR_DIGEST;
        chain_step(chain, d);
    }
    return memcmp(chain, s->chain, 32) == 0 ? CX_OK : CX_ERR_DIGEST;
}

int cx_promote(CxStore *s, uint64_t token, uint64_t candidate, uint64_t evidence,
               uint64_t t, uint64_t *out_id) {
    const CxObject *c = cx_get(s, candidate);
    const CxObject *e = cx_get(s, evidence);
    if (!c || !e || c->cls != CX_CLAIM || c->kind != CX_K_CANDIDATE || e->cls != CX_EVIDENCE)
        return CX_ERR_ARG;
    if (cx_verify(s, candidate) != CX_OK || cx_verify(s, evidence) != CX_OK) return CX_ERR_DIGEST;
    CxHeader h;
    memset(&h, 0, sizeof h);
    h.cls = CX_EVIDENCE;
    h.kind = CX_K_PROMOTION;
    h.subject = c->subject;
    h.t = t;
    h.generation = c->generation;
    h.branch = c->branch;
    h.protect = CX_PROT_VERIFY_EVIDENCE;
    h.links[0] = candidate;
    h.links[1] = evidence;
    uint64_t words[8];
    for (int i = 0; i < 4; i++) {
        words[i] = le_get(c->digest + 8 * i);
        words[4 + i] = le_get(e->digest + 8 * i);
    }
    return cx_append_as(s, token, &h, words, 8, out_id);
}

static int matches(const CxObject *o, const CxFilter *f) {
    if (!f) return 1;
    if (f->cls && o->cls != f->cls) return 0;
    if (f->kind && o->kind != f->kind) return 0;
    if (!f->branch_any && o->branch != f->branch) return 0;
    return 1;
}

/* First index in the subject list with t >= t0. */
static uint32_t lower_bound(const CxStore *s, const CxIdList *l, uint64_t t0) {
    uint32_t lo = 0, hi = l->n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (s->obj[l->ids[mid] - 1].t < t0) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

uint64_t cx_range(CxStore *s, uint64_t subject, uint64_t t0, uint64_t t1,
                  const CxFilter *f, CxVisit visit, void *user) {
    if (subject >= s->n_subjects) return 0;
    const CxIdList *l = &s->by_subject[subject];
    uint64_t visited = 0;
    for (uint32_t i = lower_bound(s, l, t0); i < l->n; i++) {
        const CxObject *o = &s->obj[l->ids[i] - 1];
        if (o->t > t1) break;
        s->examined++;
        if (!matches(o, f)) continue;
        visited++;
        if (visit && visit(user, o)) break;
    }
    return visited;
}

uint64_t cx_latest(CxStore *s, uint64_t subject, uint64_t t_max, const CxFilter *f) {
    if (subject >= s->n_subjects) return 0;
    const CxIdList *l = &s->by_subject[subject];
    uint32_t i = lower_bound(s, l, t_max == UINT64_MAX ? UINT64_MAX : t_max + 1);
    while (i > 0) {
        const CxObject *o = &s->obj[l->ids[--i] - 1];
        s->examined++;
        if (matches(o, f)) return o->id;
    }
    return 0;
}

uint64_t cx_count_before(const CxStore *s, uint64_t subject, uint64_t t0) {
    if (subject >= s->n_subjects) return 0;
    return lower_bound(s, &s->by_subject[subject], t0);
}

uint64_t cx_count_subject(const CxStore *s, uint64_t subject) {
    return subject < s->n_subjects ? s->by_subject[subject].n : 0;
}

/* ---- recall -------------------------------------------------------------- */

int cx_recall_id(const CxStore *s, uint64_t id, CxRecord *out) {
    const CxObject *o = cx_get(s, id);
    if (!o || !out) return CX_ERR_ARG;
    out->hdr = *o;
    out->payload = cx_payload(s, o);
    out->verified = cx_verify(s, id) == CX_OK;
    return out->verified ? CX_OK : CX_ERR_DIGEST;
}

typedef struct { const CxStore *s; CxRecord *out; uint32_t n, max; } RecallCtx;

static int recall_visit(void *user, const CxObject *o) {
    RecallCtx *c = user;
    cx_recall_id(c->s, o->id, &c->out[c->n++]);
    return c->n >= c->max;
}

uint32_t cx_recall(CxStore *s, uint64_t subject, uint64_t t0, uint64_t t1,
                   const CxFilter *f, CxRecord *out, uint32_t max) {
    if (!s || !out || max == 0) return 0;
    RecallCtx c = { s, out, 0, max };
    cx_range(s, subject, t0, t1, f, recall_visit, &c);
    return c.n;
}

uint32_t cx_provenance(const CxStore *s, uint64_t id, uint64_t *out, uint32_t max) {
    if (!s || !out || !cx_get(s, id)) return 0;
    uint32_t n = 0, head = 0;
    /* Breadth first over `out` itself; links always point to older ids. */
    uint64_t cur = id;
    for (;;) {
        const CxObject *o = cx_get(s, cur);
        for (uint32_t i = 0; o && i < CX_LINKS && n < max; i++) {
            uint64_t l = o->links[i];
            if (l == 0 || l >= cur || l == id) continue;
            int seen = 0;
            for (uint32_t j = 0; j < n && !seen; j++) seen = out[j] == l;
            if (!seen) out[n++] = l;
        }
        if (head >= n || n >= max) break;
        cur = out[head++];
    }
    return n;
}

int cx_world_decode(const CxRecord *r, CxWorldRecord *out) {
    if (!r || !out || r->hdr.kind < CX_K_WORK_ACCEPTED || r->hdr.kind > CX_K_EXEC_FAILED ||
        r->hdr.n != CX_WREC_WORDS)
        return CX_ERR_ARG;
    const uint64_t *p = r->payload;
    memset(out, 0, sizeof(*out));
    out->cx_id = r->hdr.id;
    out->kind = r->hdr.kind;
    out->session = p[CX_WREC_SESSION];
    out->crumb = p[CX_WREC_CRUMB];
    out->crumb_kind = (uint32_t)p[CX_WREC_CRUMB_KIND];
    out->reaction = (uint32_t)p[CX_WREC_REACTION];
    out->faculty = (uint32_t)p[CX_WREC_FACULTY];
    out->episode = p[CX_WREC_EPISODE];
    out->reason = (int32_t)(int64_t)p[CX_WREC_REASON];
    out->obj = p[CX_WREC_OBJ];
    out->obj_gen = p[CX_WREC_OBJ_GEN];
    out->obj_version = p[CX_WREC_OBJ_VERSION];
    for (int i = 0; i < 8; i++) out->field[i] = p[CX_WREC_FIELD0 + i];
    for (int i = 0; i < 4; i++) le_put(out->crumb_digest + 8 * i, p[CX_WREC_DIGEST0 + i]);
    out->n_inputs = (uint32_t)p[CX_WREC_N_INPUTS];
    out->n_outputs = (uint32_t)p[CX_WREC_N_OUTPUTS];
    out->cause = r->hdr.links[0];
    return CX_OK;
}

void cx_tamper(CxStore *s, uint64_t id, uint32_t word, uint64_t value) {
    const CxObject *o = cx_get(s, id);
    if (o && word < o->n) s->arena[o->off + word] = value;
}
