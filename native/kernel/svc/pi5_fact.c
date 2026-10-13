/* pi5_fact.c -- see pi5_fact.h. */
#include "pi5_fact.h"
#include <stddef.h>
#include "ck.h"
#include "cortex_journal.h"

#define FACT_HEAP_BYTES (512u * 1024u) /* replay of a journal of a few facts peaks well below this */
static uint8_t g_heap[FACT_HEAP_BYTES] __attribute__((aligned(16)));
static ck_cj g_cj;
static CxStore g_cx;

static uint32_t journal_chunks(const ss_store *s)
{
    uint32_t k, n = 0;
    for (k = 0; k < s->nclaims; k++)
        if (s->ws->claims[k].c.obj.object_kind == CK_CJ_KIND) n++;
    return n;
}

static void show(char *out, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) out[i] = (b[i] >= 0x20 && b[i] <= 0x7e) ? (char)b[i] : '?';
    out[n] = 0;
}

/* Same record as core/lifecycle.c remember(): payload = text packed into little-endian 64-bit words,
 * tag = byte length, t = record count + 1, generation = the Store generation this append commits. */
static int remember(ss_store *s, const struct ck_fact_req_boot *req)
{
    uint64_t pay[(CK_FACT_REQ_TEXT_MAX + 7) / 8];
    uint32_t nw = (req->len + 7) / 8, i;
    CxHeader h;
    uint64_t id = 0;
    for (i = 0; i < nw; i++) pay[i] = 0;
    for (i = 0; i < req->len; i++) pay[i / 8] |= (uint64_t)req->text[i] << (8 * (i % 8));
    for (i = 0; i < sizeof h; i++) ((uint8_t *)&h)[i] = 0;
    h.cls = CX_CLAIM;
    h.kind = CX_K_CLAIM;
    h.subject = CK_CX_FACT_SUBJECT;
    h.t = g_cx.n + 1;
    h.generation = ss_generation(s) + 1;
    h.tag = req->len;
#ifdef CK_FACT_MUTANT_NO_APPEND
    /* TEST-ONLY mutant: skip the commit but still report success. */
    int rc = CX_OK;
    id = g_cx.n + 1;
#else
    int rc = cx_append(&g_cx, &h, pay, nw, &id);
#endif
    if (rc != CX_OK) {
        ck_printf("fact_stage: REFUSED remember rc=%d reason=\"cortex append failed, nothing written\"\n", rc);
        return -1;
    }
    {
        char shown[CK_FACT_REQ_TEXT_MAX + 1];
        show(shown, req->text, req->len);
        ck_printf("fact_stage: remembered id=%llu t=%llu store_gen=%llu bytes=%u text=\"%s\"\n",
                  (unsigned long long)id, (unsigned long long)h.t, (unsigned long long)ss_generation(s),
                  (unsigned)req->len, shown);
    }
    return 0;
}

/* Every fact, oldest first (label "readback" right after a remember in the same boot, "recalled" on a later boot), each read back through cx_recall_id (digest re-checked); then the chain. */
static int recall(ss_store *s, struct ck_fact_result *out, const char *label)
{
    static CxRecord r;
    uint64_t id;
    (void)s;
    for (id = 1; id <= g_cx.n; id++) {
        uint8_t text[CK_FACT_REQ_TEXT_MAX];
        char shown[CK_FACT_REQ_TEXT_MAX + 1];
        size_t len, i;
        if (cx_recall_id(&g_cx, id, &r) != CX_OK || !r.verified) {
            ck_printf("fact_stage: fact id=%llu DIGEST_FAIL\n", (unsigned long long)id);
            continue;
        }
        if (r.hdr.cls != CX_CLAIM || r.hdr.kind != CX_K_CLAIM || r.hdr.subject != CK_CX_FACT_SUBJECT) continue;
        len = (size_t)r.hdr.tag;
        if (len > sizeof text || len > (size_t)r.hdr.n * 8) len = 0;
        for (i = 0; i < len; i++) text[i] = (uint8_t)(r.payload[i / 8] >> (8 * (i % 8)));
        show(shown, text, len);
        ck_printf("fact_stage: %s id=%llu t=%llu store_gen=%llu text=\"%s\"\n", label, (unsigned long long)id,
                  (unsigned long long)r.hdr.t, (unsigned long long)r.hdr.generation, shown);
        out->shown++;
        out->last_id = id;
        out->last_gen = r.hdr.generation;
    }
    return 0;
}

int ck_pi5_fact_run(ss_store *s, const struct ck_fact_req_boot *req, struct ck_fact_result *out)
{
    struct ck_fact_result z = {0};
    int want_write = req && req->state == CK_FACT_REQ_FOUND;
    int rc;
    *out = z;
    if (!s) {
        out->mode = CK_FACT_MODE_NOSTORE;
        ck_puts("fact_stage: NOTHING RECALLED: the Store is not open (recovery secret missing or rejected, or the disk "
                "was refused); no Cortex was read, nothing was written\n");
        return 0;
    }
    out->mode = want_write ? CK_FACT_MODE_REMEMBER : CK_FACT_MODE_RECALL;
#ifdef CK_FACT_MUTANT_RECALL_BLIND
    /* TEST-ONLY mutant: recall never looks at the journal. */
    if (!want_write) {
#else
    if (!want_write && journal_chunks(s) == 0) {
#endif
        ck_puts("fact_stage: recall none cortex=none records=0 (no journal on this disk; nothing created)\n");
        out->chain_ok = 1;
        return 0;
    }
    ck_cx_heap_init(g_heap, sizeof g_heap);
    ck_cj_init(&g_cj, s);
    rc = cx_open_with(&g_cx, &ck_cx_journal_store, &g_cj, "cortex", CK_CX_SUBJECTS, 0);
    if (rc != CX_OK) {
        ck_printf("fact_stage: REFUSED cortex open rc=%d chunks=%u\n", rc, journal_chunks(s));
        return -1;
    }
    ck_printf("fact_stage: cortex open records=%llu chunks=%u journal_bytes=%u store_gen=%llu chain=%s\n",
              (unsigned long long)g_cx.n, g_cj.nchunks, (unsigned)g_cj.len, (unsigned long long)ss_generation(s),
              cx_verify_chain(&g_cx) == CX_OK ? "ok" : "FAIL");
    rc = want_write ? remember(s, req) : 0;
    if (rc == 0) {
        /* Read everything back the way a cold boot would: from the journal replayed at open (remember
         * appended to the open store, which is the same state a replay rebuilds). */
        rc = recall(s, out, want_write ? "readback" : "recalled");
    }
    out->records = g_cx.n;
    out->chain_ok = cx_verify_chain(&g_cx) == CX_OK;
    ck_printf("fact_stage: %s records=%llu shown=%llu newest_id=%llu newest_store_gen=%llu journal_bytes=%u chain=%s\n",
              want_write ? "remember" : "recall", (unsigned long long)out->records, (unsigned long long)out->shown,
              (unsigned long long)out->last_id, (unsigned long long)out->last_gen, (unsigned)g_cj.len,
              out->chain_ok ? "ok" : "FAIL");
    cx_close(&g_cx);
    return rc;
}
