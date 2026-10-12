/* cortex_journal.c -- CxJournalOps over the sealed Store, and the bounded
 * Cortex heap. See cortex_journal.h. No I/O except through ss_read /
 * ss_transact; no libc beyond the four memory routines. */
#include "cortex_journal.h"

#include <string.h>

/* ---- heap ---------------------------------------------------------------- */
static struct {
    uint8_t *base;
    size_t size, used, peak;
} g_h;

void ck_cx_heap_init(void *base, size_t size)
{
    g_h.base = base;
    g_h.size = base ? size : 0;
    g_h.used = 0;
    g_h.peak = 0;
}

void ck_cx_heap_stats(size_t *used, size_t *peak, size_t *size)
{
    if (used) *used = g_h.used;
    if (peak) *peak = g_h.peak;
    if (size) *size = g_h.size;
}

/* Each block carries its size in the 16 bytes before it (16-byte alignment). */
void *ck_cx_alloc(size_t n)
{
    size_t need = (n + 15u) & ~(size_t)15u;
    if (!g_h.base || need > g_h.size - g_h.used || g_h.size - g_h.used - need < 16u) return 0;
    uint8_t *p = g_h.base + g_h.used + 16u;
    ((size_t *)(p - 16u))[0] = n;
    g_h.used += need + 16u;
    if (g_h.used > g_h.peak) g_h.peak = g_h.used;
    return p;
}

void *ck_cx_realloc(void *p, size_t n)
{
    if (!p) return ck_cx_alloc(n);
    size_t old = ((size_t *)((uint8_t *)p - 16u))[0];
    if (n <= old) return p;
    void *q = ck_cx_alloc(n);
    if (!q) return 0;
    memcpy(q, p, old);
    return q;
}

void ck_cx_free(void *p) { (void)p; }

/* ---- journal ------------------------------------------------------------- */
void ck_cj_init(ck_cj *j, ss_store *s)
{
    memset(j, 0, sizeof *j);
    j->s = s;
}

/* Rebuild the chunk index from the Store's verified claims, ordered by
 * (store generation, object sequence): the order the chunks were committed. */
static int cj_index(ck_cj *j)
{
    uint32_t k, i;
    j->nchunks = 0;
    j->len = 0;
    for (k = 0; k < j->s->nclaims; k++) {
        const ss_claim *c = &j->s->ws->claims[k];
        if (c->c.obj.object_kind != CK_CJ_KIND) continue;
        if (j->nchunks >= CK_CJ_MAX_CHUNKS) return CX_ERR_IO;
        ck_cj_chunk e;
        memcpy(e.sid, c->sid, 32);
        e.gen = c->c.store_generation;
        e.seq = c->c.object_sequence;
        e.len = 0;
        for (i = j->nchunks; i > 0; i--) {
            const ck_cj_chunk *p = &j->chunks[i - 1];
            if (p->gen < e.gen || (p->gen == e.gen && p->seq < e.seq)) break;
            j->chunks[i] = *p;
        }
        j->chunks[i] = e;
        j->nchunks++;
    }
    /* Lengths come from the envelopes themselves (one decrypt per chunk). */
    for (k = 0; k < j->nchunks; k++) {
        size_t n = 0;
        uint16_t kind = 0;
        if (ss_read(j->s, j->chunks[k].sid, j->buf, sizeof j->buf, &n, &kind) != 0 || kind != CK_CJ_KIND) return CX_ERR_IO;
        j->chunks[k].len = (uint32_t)n;
        j->len += n;
    }
    return CX_OK;
}

static int cj_open(void *ctx, const char *name, int ro, void **h)
{
    ck_cj *j = ctx;
    if (!j || !j->s || !name || !h) return CX_ERR_ARG;
    if (!ro && j->writer) { j->refused++; return CX_ERR_WRITER; }
    int rc = cj_index(j);
    if (rc != CX_OK) return rc;
    if (ro) { j->ro_handles++; *h = &j->ro_handles; }
    else { j->writer = 1; *h = j; }
    return CX_OK;
}

static int cj_size(void *ctx, void *h, size_t *len)
{
    (void)h;
    *len = ((ck_cj *)ctx)->len;
    return CX_OK;
}

static int cj_read(void *ctx, void *h, size_t off, uint8_t *out, size_t n)
{
    ck_cj *j = ctx;
    (void)h;
    if (off + n > j->len) return CX_ERR_IO;
    size_t pos = 0;
    uint32_t k;
    j->reads++;
    for (k = 0; k < j->nchunks && n; k++) {
        size_t cl = j->chunks[k].len;
        if (off >= pos + cl) { pos += cl; continue; }
        size_t got = 0;
        uint16_t kind = 0;
        if (ss_read(j->s, j->chunks[k].sid, j->buf, sizeof j->buf, &got, &kind) != 0 || got != cl) return CX_ERR_IO;
        size_t start = off - pos, take = cl - start;
        if (take > n) take = n;
        memcpy(out, j->buf + start, take);
        out += take;
        off += take;
        n -= take;
        pos += cl;
    }
    return n ? CX_ERR_IO : CX_OK;
}

/* One append = one sealed transaction: all chunks durable or none. sync is
 * implied (ss_transact returns after the generation is durable). */
static int cj_append(void *ctx, void *h, const uint8_t *b, size_t n, int sync)
{
    ck_cj *j = ctx;
    (void)sync;
    if (h != (void *)j) return CX_ERR_IO; /* read-only handle */
    if (n == 0) return CX_OK;
    if (n > CK_CJ_MAX_RECORD) { j->refused++; return CX_ERR_IO; }
    size_t k = (n + SS_MAX_PLAINTEXT - 1) / SS_MAX_PLAINTEXT;
    if (j->nchunks + k > CK_CJ_MAX_CHUNKS) { j->refused++; return CX_ERR_IO; }
    ss_object objs[SS_MAX_OBJECTS];
    uint8_t ids[SS_MAX_OBJECTS][32];
    size_t i, left = n;
    for (i = 0; i < k; i++) {
        size_t cl = left > SS_MAX_PLAINTEXT ? SS_MAX_PLAINTEXT : left;
        objs[i].kind = CK_CJ_KIND;
        objs[i].version = 1;
        objs[i].bytes = b + i * SS_MAX_PLAINTEXT;
        objs[i].len = cl;
        left -= cl;
    }
    if (ss_transact(j->s, objs, k, 0, 0, ids) != 0) return CX_ERR_IO;
    uint64_t gen = ss_generation(j->s);
    for (i = 0; i < k; i++) {
        ck_cj_chunk *e = &j->chunks[j->nchunks++];
        memcpy(e->sid, ids[i], 32);
        e->gen = gen;
        e->seq = i;
        e->len = (uint32_t)objs[i].len;
        j->len += objs[i].len;
    }
    j->appends++;
    return CX_OK;
}

/* Appends are atomic, so the journal never holds a torn tail: only the
 * current length is accepted. */
static int cj_truncate(void *ctx, void *h, size_t len)
{
    ck_cj *j = ctx;
    if (h != (void *)j) return CX_ERR_IO;
    return len == j->len ? CX_OK : CX_ERR_IO;
}

static void cj_close(void *ctx, void *h)
{
    ck_cj *j = ctx;
    if (h == (void *)j) j->writer = 0;
    else if (j->ro_handles) j->ro_handles--;
}

const CxJournalOps ck_cx_journal_store = { cj_open, cj_size, cj_read, cj_append, cj_truncate, cj_close };
